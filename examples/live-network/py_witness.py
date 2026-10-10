"""A tlog-witness witness in ~40 lines of Python on witness_log.WitnessService.

usage: py_witness.py <dir> <port> <key-name> <org> <compute> [--evil MODE]
MODE (for Byzantine testing only): wrongkey | wrongcheckpoint | garbage | stale
"""
import json, os, sys, time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import witness_log as wl

d, port, name, org, compute = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
evil = sys.argv[sys.argv.index("--evil") + 1] if "--evil" in sys.argv else None
seed = bytes.fromhex(open(os.path.join(d, "seed.hex")).read().strip())
svc = wl.WitnessService.new(name, seed, os.path.join(d, "state.json"), True)
entry = json.loads(wl.witness_entry_independent(name, org, f"http://127.0.0.1:{port}", svc.pubkey_hex(), compute))
other = wl.WitnessService.new(name, os.urandom(32), None, True)  # for evil=wrongkey (in-memory)

MAX = 64 * 1024


class H(BaseHTTPRequestHandler):
    timeout = 10

    def log_message(self, *a):
        pass

    def send(self, st, ctype, body):
        b = body.encode()
        self.send_response(st)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path == "/":
            self.send(200, "application/json", json.dumps({
                "software": "witness-log python witness", "key_name": name,
                "pubkey_hex": svc.pubkey_hex(), "vkey": svc.vkey(),
                "logs": svc.log_count(), "directory_entry": entry}))
        elif self.path == "/health":
            self.send(200, "text/plain", "ok\n")
        else:
            self.send(404, "text/plain", "not found\n")

    def do_POST(self):
        if self.path != "/add-checkpoint":
            return self.send(404, "text/plain", "not found\n")
        n = int(self.headers.get("Content-Length") or -1)
        if n < 0:
            return self.send(411, "text/plain", "length required\n")
        if n > MAX:
            return self.send(413, "text/plain", "too large\n")
        try:
            body = self.rfile.read(n).decode()
        except UnicodeDecodeError:
            return self.send(400, "text/plain", "not utf-8\n")
        if evil == "garbage":
            return self.send(200, "text/plain", "— " + name + " AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n")
        if evil == "wrongkey":
            st, ct, out = other.handle_add_checkpoint_http(body)
            return self.send(st, ct, out)
        if evil == "wrongcheckpoint":
            # Cosign a different (made-up) head and return that.
            st, ct, out = svc.handle_add_checkpoint_http(body)
            if st == 200:
                parts = out.split(" ")
                import base64
                raw = bytearray(base64.b64decode(parts[2]))
                raw[20] ^= 0xFF  # corrupt the signature bytes
                parts[2] = base64.b64encode(bytes(raw)).decode() + "\n"
                out = " ".join(parts)
            return self.send(st, ct, out)
        st, ct, out = svc.handle_add_checkpoint_http(body)
        self.send(st, ct, out)


class Server(ThreadingHTTPServer):
    daemon_threads = True
    # http.server's default listen backlog is 5: fifty agents connecting at
    # once get "connection refused". Found by the 50-agent live run.
    request_queue_size = 128


Server(("127.0.0.1", port), H).serve_forever()
