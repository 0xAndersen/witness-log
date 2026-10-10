"""Live witness network harness: real processes, real sockets.

8 Rust witnesses (`witness-log witness serve`) + 2 Python witnesses
(witness_log.WitnessService behind http.server), each its own process,
own key, own state directory, distinct operator and compute provider.
"""
import json, os, signal, socket, subprocess, sys, time, urllib.request, urllib.error

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
BIN = os.environ.get("WL_BIN", os.path.join(REPO, "target", "release", "witness-log"))
PY = sys.executable
HERE = os.path.dirname(os.path.abspath(__file__))
BASE_PORT = 17300

OPERATORS = [
    ("Acme Labs", "aws"), ("Borealis Inc", "gcp"), ("Cobalt Co", "azure"),
    ("Delta Org", "hetzner"), ("Ember LLC", "ovh"), ("Fjord AS", "self-hosted"),
    ("Granite Ltd", "aws"), ("Harbor GmbH", "gcp"), ("Iris Foundation", "digitalocean"),
    ("Juniper DAO", "self-hosted"),
]


def free(port):
    with socket.socket() as s:
        return s.connect_ex(("127.0.0.1", port)) != 0


def wait_up(port, timeout=10):
    t = time.time()
    while time.time() - t < timeout:
        if not free(port):
            return True
        time.sleep(0.05)
    return False


def http(method, url, body=None, timeout=10, headers=None):
    """Returns (status, body, content_type); status 0 on connection failure."""
    req = urllib.request.Request(url, data=body.encode() if isinstance(body, str) else body,
                                 method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode(), r.headers.get("Content-Type")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), e.headers.get("Content-Type")
    except (urllib.error.URLError, ConnectionError, OSError) as e:
        return 0, str(e), None


class Witness:
    def __init__(self, idx, root, kind):
        self.idx, self.kind = idx, kind
        self.port = BASE_PORT + idx
        self.url = f"http://127.0.0.1:{self.port}"
        self.dir = os.path.join(root, f"w{idx}")
        self.org, self.compute = OPERATORS[idx % len(OPERATORS)]
        self.name = f"w{idx}.witness.test/{self.org.split()[0].lower()}"
        self.proc = None
        self.entry = None

    def init(self):
        os.makedirs(self.dir, exist_ok=True)
        if self.kind == "rust":
            r = subprocess.run([BIN, "witness", "init", self.dir, "--name", self.name,
                                "--org", self.org, "--url", self.url, "--compute", self.compute],
                               capture_output=True, text=True)
            assert r.returncode == 0, r.stderr
            self.entry = json.loads(r.stdout)
        else:
            seed = os.urandom(32)
            with open(os.path.join(self.dir, "seed.hex"), "w") as f:
                f.write(seed.hex())
            os.chmod(os.path.join(self.dir, "seed.hex"), 0o600)
            import witness_log
            witness_log.WitnessService.create_state(os.path.join(self.dir, "state.json"))

    def start(self, extra=()):
        log = open(os.path.join(self.dir, "server.log"), "ab")
        if self.kind == "rust":
            cmd = [BIN, "witness", "serve", self.dir, "--listen", f"127.0.0.1:{self.port}",
                   "--open-enrollment", *extra]
        else:
            cmd = [PY, os.path.join(HERE, "py_witness.py"), self.dir, str(self.port), self.name,
                   self.org, self.compute, *extra]
        self.proc = subprocess.Popen(cmd, stdout=log, stderr=log)
        assert wait_up(self.port), f"{self.name} did not come up; see {self.dir}/server.log"
        st, body, _ = http("GET", self.url + "/")
        assert st == 200, body
        info = json.loads(body)
        self.entry = info["directory_entry"]
        return info

    def kill(self, sig=signal.SIGKILL):
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(sig)
            self.proc.wait(timeout=10)
        self.proc = None
        t = time.time()
        while not free(self.port) and time.time() - t < 5:
            time.sleep(0.05)


def start_network(root, n_rust=8, n_py=2):
    ws = [Witness(i, root, "rust" if i < n_rust else "py") for i in range(n_rust + n_py)]
    for w in ws:
        w.init()
        w.start()
    return ws


def directory(ws):
    return {"witnesses": [w.entry for w in ws]}


def cli(*args, timeout=120):
    r = subprocess.run([BIN, *args], capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout, r.stderr
