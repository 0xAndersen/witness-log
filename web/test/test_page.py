"""Browser test for web/: load the page from a local static server, drop a
golden dossier and its trusted directory, and check the verdict the page
prints. Runs against whichever engine is built (web/build.sh or
web/build-go.sh). Usage: python3 web/test/test_page.py
"""
import http.server
import json
import pathlib
import sys
import threading

from playwright.sync_api import sync_playwright

ROOT = pathlib.Path(__file__).resolve().parents[2]
WEB = ROOT / "web"
GOLD = ROOT / "clients" / "go" / "testdata" / "c2sp"


def serve():
    handler = lambda *a, **k: http.server.SimpleHTTPRequestHandler(*a, directory=str(WEB), **k)  # noqa: E731
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def main() -> int:
    if not (WEB / "pkg" / "witness_log_wasm.js").exists() and not (WEB / "pkg-go" / "witness_log_go.js").exists():
        print("no engine built: run web/build.sh or web/build-go.sh", file=sys.stderr)
        return 2
    httpd = serve()
    engines = [name for name, d in (("rust", WEB / "pkg"), ("go", WEB / "pkg-go")) if d.exists()]
    print("engines built:", ", ".join(engines))
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    failures = []
    with sync_playwright() as p:
        browser = p.chromium.launch()
        for engine in engines:
            try:
                run_engine(browser, base, engine, failures)
            except Exception as e:  # noqa: BLE001
                failures.append(f"{engine}: {type(e).__name__}: {str(e).splitlines()[0]}")
        browser.close()
    httpd.shutdown()
    for f in failures:
        print("FAIL", f, file=sys.stderr)
        print(f"::error::browser verifier: {f}")
    return 1 if failures else 0


def wait_for(page, expr, timeout=30000):
    """Poll a JS expression with page.evaluate. Playwright's
    wait_for_function evaluates its predicate as a string inside the page,
    which the page's Content-Security-Policy (no 'unsafe-eval') refuses;
    page.evaluate goes through the debugging protocol and is not subject
    to it, so the page is tested under its real policy."""
    import time
    deadline = time.monotonic() + timeout / 1000
    while True:
        if page.evaluate(expr):
            return
        if time.monotonic() > deadline:
            raise TimeoutError(f"timed out waiting for {expr}")
        time.sleep(0.05)


def run_engine(browser, base, engine, failures):
        page = browser.new_page()
        console = []
        page.on("console", lambda m: console.append(f"{m.type}: {m.text}"))
        page.on("pageerror", lambda e: console.append(f"pageerror: {e}"))
        page.goto(f"{base}/index.html?engine={engine}")
        try:
            wait_for(page, "document.getElementById('engine').textContent.startsWith('engine:')", timeout=30000)
        except Exception:
            failures.append(f"{engine}: engine did not load; status={page.text_content('#status')!r}; console={console[-5:]}")
            return
        print(page.text_content("#engine"))
        csp = [c for c in console if "Content Security Policy" in c]
        if csp:
            failures.append(f"{engine}: the page breaks its own Content-Security-Policy: {csp[:3]}")

        # WITNESSED with the directory
        page.set_input_files("#input-dossier", str(GOLD / "a.json"))
        page.set_input_files("#input-directory", str(GOLD / "trusted.json"))
        page.click("#verify")
        wait_for(page, "document.getElementById('verdict-word').textContent.length > 0")
        got = page.text_content("#verdict-word")
        want = json.loads((GOLD.parent / "expect" / "c2sp-a.directory.json").read_text())["verdict"]
        print("with directory:", got)
        if got != want:
            failures.append(f"{engine} with directory: got {got}, want {want}")

        # Tampered dossier -> INVALID (DIVERGED before 0.5.0)
        tampered = json.loads((GOLD / "a.json").read_text())
        tampered["leaves"][0]["payload_hash"] = "00" * 32
        tmp = WEB / "test" / "_tampered.json"
        tmp.write_text(json.dumps(tampered))
        try:
            page.set_input_files("#input-dossier", str(tmp))
            page.click("#verify")
            try:
                wait_for(page, "document.getElementById('verdict-word').textContent === 'INVALID'", timeout=10000)
            except Exception:
                failures.append(f"{engine} tampered: got {page.text_content('#verdict-word')!r}, status={page.text_content('#status')!r}")
            print("tampered:", page.text_content("#verdict-word"))
            # An INVALID dossier's known heads are never compared: no tick
            # for them (security review of 0.5.0, F9).
            page.fill("#known-heads", "1:" + "ab" * 32)
            page.click("#verify")
            wait_for(page, "document.getElementById('verdict-word').textContent === 'INVALID'", timeout=10000)
            if "known heads" in (page.text_content("#checks") or ""):
                failures.append(f"{engine} tampered + known head: the page reports on heads it never compared")
            page.fill("#known-heads", "")
        finally:
            tmp.unlink(missing_ok=True)

        # A head larger than the dossier is "not checked" (–), never ticked.
        page.set_input_files("#input-dossier", str(GOLD / "a.json"))
        page.fill("#known-heads", "999999:" + "ab" * 32)
        page.click("#verify")
        wait_for(page, "document.getElementById('checks').textContent.includes('known heads not checked')", timeout=10000)
        heads_rows = page.eval_on_selector_all(
            "#checks li", "els => els.filter(e => e.textContent.includes('known heads')).map(e => e.className)")
        if heads_rows != ["skip"]:
            failures.append(f"{engine} unchecked known head: rows {heads_rows}, want one not-checked row")
        page.fill("#known-heads", "")

        # A known head the dossier does not reproduce -> DIVERGED (0.5.0)
        page.set_input_files("#input-dossier", str(GOLD / "a.json"))
        page.fill("#known-heads", "1:" + "ab" * 32)
        page.click("#verify")
        try:
            wait_for(page, "document.getElementById('verdict-word').textContent === 'DIVERGED'", timeout=10000)
        except Exception:
            failures.append(f"{engine} known head: got {page.text_content('#verdict-word')!r}, status={page.text_content('#status')!r}")
        print("contradicted known head:", page.text_content("#verdict-word"), page.text_content("#verdict-exit")[:40])
        if "exit 30" not in (page.text_content("#verdict-exit") or ""):
            failures.append(f"{engine} known head: {page.text_content('#verdict-exit')!r}")
        page.fill("#known-heads", "")

        # bind a.json with b.json
        page.set_input_files("#input-dossier", str(GOLD / "a.json"))
        page.set_input_files("#input-other", str(GOLD / "b.json"))
        wait_for(page, "document.getElementById('bind-out').textContent.length > 0", timeout=10000)
        bind_out = page.text_content("#bind-out")
        print("bind:", bind_out[:80])
        want_exit = (GOLD / "bind.expected.exit").read_text().strip()
        if f"exit {want_exit}" not in bind_out:
            failures.append(f"{engine} bind: expected exit {want_exit} in: {bind_out[:200]}")
        errs = [c for c in console if c.startswith("error") or c.startswith("pageerror")]
        if errs:
            failures.append(f"{engine}: console errors: {errs[:5]}")
        page.close()


if __name__ == "__main__":
    sys.exit(main())
