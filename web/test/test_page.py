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
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    failures = []
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto(f"{base}/index.html")
        page.wait_for_function("document.getElementById('engine').textContent.startsWith('engine:')", timeout=30000)
        print(page.text_content("#engine"))

        # WITNESSED with the directory
        page.set_input_files("#input-dossier", str(GOLD / "a.json"))
        page.set_input_files("#input-directory", str(GOLD / "trusted.json"))
        page.click("#verify")
        page.wait_for_function("document.getElementById('verdict-word').textContent.length > 0")
        got = page.text_content("#verdict-word")
        want = json.loads((GOLD.parent / "expect" / "c2sp-a.directory.json").read_text())["verdict"]
        print("with directory:", got)
        if got != want:
            failures.append(f"with directory: got {got}, want {want}")

        # Tampered dossier -> DIVERGED
        tampered = json.loads((GOLD / "a.json").read_text())
        tampered["leaves"][0]["payload_hash"] = "00" * 32
        tmp = WEB / "test" / "_tampered.json"
        tmp.write_text(json.dumps(tampered))
        try:
            page.set_input_files("#input-dossier", str(tmp))
            page.click("#verify")
            page.wait_for_function("document.getElementById('verdict-word').textContent === 'DIVERGED'", timeout=10000)
            print("tampered:", page.text_content("#verdict-word"))
        finally:
            tmp.unlink(missing_ok=True)

        # bind a.json with b.json
        page.set_input_files("#input-dossier", str(GOLD / "a.json"))
        page.set_input_files("#input-other", str(GOLD / "b.json"))
        page.wait_for_function("document.getElementById('bind-out').textContent.length > 0", timeout=10000)
        bind_out = page.text_content("#bind-out")
        print("bind:", bind_out[:80])
        want_exit = (GOLD / "bind.expected.exit").read_text().strip()
        if f"exit {want_exit}" not in bind_out:
            failures.append(f"bind: expected exit {want_exit} in: {bind_out[:200]}")
        browser.close()
    httpd.shutdown()
    for f in failures:
        print("FAIL", f, file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
