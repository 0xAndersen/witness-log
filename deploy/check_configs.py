#!/usr/bin/env python3
"""Check the one-click deploy files against each other and the image.

render.yaml (repository root) and deploy/fly/fly.toml both build
deploy/witness/Dockerfile and run its entrypoint. This script checks that
they parse, that every file they name exists, and that they agree with the
image on what keeps a witness a witness: the state on a persistent mount at
/state (and no VOLUME in the image to fake one), one instance that never
starts by itself once stopped, the health path, the port, the operator's
organisation left for the operator to fill in, and the build argument that
lets the entrypoint take ownership of a root-owned mount.

  check_configs.py                 check; exit 1 and list every problem
  check_configs.py --emit render   print what the platform would run, as JSON
  check_configs.py --emit fly      (dockerfile, context, build_args, env,
                                    port, mount, health); CI runs the image
                                    with exactly these values

Needs Python 3.11+ (tomllib) and PyYAML.
"""
import json
import os
import re
import sys
import tomllib

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RENDER = os.path.join(ROOT, "render.yaml")
FLY = os.path.join(ROOT, "deploy", "fly", "fly.toml")
FLY_README = os.path.join(ROOT, "deploy", "fly", "README.md")
ENTRYPOINT = os.path.join(ROOT, "deploy", "witness", "docker-entrypoint.sh")
ONBOARDING = os.path.join(ROOT, "docs", "wiki", "Operator-Onboarding.md")
RENDER_BUTTON = "https://render.com/deploy?repo=https://github.com/0xAndersen/witness-log"

STATE = "/state"
HEALTH = "/health"
ROOT_START = "0:0"


def rel(path):
    return os.path.relpath(path, ROOT)


def repo_path(p):
    """A path from a config file, relative to the repository root."""
    p = p[2:] if p.startswith("./") else p
    return os.path.normpath(os.path.join(ROOT, p))


def image_facts(dockerfile, problems):
    """Port, volume and build arguments the Dockerfile's final stage declares."""
    text = open(dockerfile, encoding="utf-8").read()
    final = text[text.rfind("\nFROM "):] if "\nFROM " in text else text
    facts = {
        "expose": [int(p) for p in re.findall(r"^EXPOSE\s+(\d+)", final, re.M)],
        "volumes": re.findall(r"^VOLUME\s+(.+)$", final, re.M),
        "args": dict(re.findall(r"^ARG\s+([A-Za-z_][A-Za-z0-9_]*)(?:=(\S*))?", final, re.M)),
        "env": dict(re.findall(r"^ENV\s+([A-Za-z_][A-Za-z0-9_]*)=(\S*)", final, re.M)),
        "entrypoint": re.findall(r"^ENTRYPOINT\s+(.+)$", final, re.M),
        "cmd": re.findall(r"^CMD\s+", final, re.M),
    }
    if facts["volumes"]:
        # With VOLUME, a run without a mount gets an anonymous volume that
        # passes the entrypoint's mount check and is lost with the container.
        problems.append(f"{rel(dockerfile)}: must not declare VOLUME; the state mount comes from the "
                        f"platform's disk or `-v`, and the entrypoint refuses to create a key without one")
    if "WITNESS_IMAGE_USER" not in facts["args"]:
        problems.append(f"{rel(dockerfile)}: final stage has no ARG WITNESS_IMAGE_USER for the configs to set")
    if facts["env"].get("WITNESS_IMAGE_USER") != "${WITNESS_IMAGE_USER}":
        problems.append(f"{rel(dockerfile)}: final stage must pass the build argument on as "
                        "ENV WITNESS_IMAGE_USER=${WITNESS_IMAGE_USER}; the entrypoint changes ownership only then")
    if not any("docker-entrypoint.sh" in e for e in facts["entrypoint"]):
        problems.append(f"{rel(dockerfile)}: ENTRYPOINT must be docker-entrypoint.sh (the configs rely on it)")
    if facts["cmd"]:
        problems.append(f"{rel(dockerfile)}: a CMD would bypass the entrypoint's init-and-serve path")
    return facts


def listen_port(problems):
    m = re.search(r"WITNESS_LISTEN:-0\.0\.0\.0:(\d+)", open(ENTRYPOINT, encoding="utf-8").read())
    if not m:
        problems.append(f"{rel(ENTRYPOINT)}: cannot find the default WITNESS_LISTEN port")
        return None
    return int(m.group(1))


def check_render(problems):
    try:
        doc = yaml.safe_load(open(RENDER, encoding="utf-8"))
    except (OSError, yaml.YAMLError) as e:
        problems.append(f"render.yaml: {e}")
        return None
    services = doc.get("services") if isinstance(doc, dict) else None
    if not isinstance(services, list) or len(services) != 1:
        problems.append("render.yaml: needs exactly one service")
        return None
    s = services[0]
    p = lambda msg: problems.append(f"render.yaml: {msg}")  # noqa: E731
    if s.get("type") != "web":
        p("type must be web (it needs a public URL and a health check)")
    if s.get("runtime") != "docker":
        p("runtime must be docker (build from the repository, not a pulled image)")
    if s.get("plan") in (None, "free"):
        p("plan must be a paid instance: free instances cannot attach a disk")
    if s.get("numInstances") != 1:
        p("numInstances must be 1: a second copy of one witness must never run")
    if s.get("autoDeployTrigger") != "off":
        p("autoDeployTrigger must be the string \"off\": pushes here must not redeploy an operator's witness")
    if "dockerCommand" in s:
        p("dockerCommand would bypass the entrypoint that the CI job tests")
    if s.get("healthCheckPath") != HEALTH:
        p(f"healthCheckPath must be {HEALTH}")
    dockerfile = repo_path(s.get("dockerfilePath", "./Dockerfile"))
    context = repo_path(s.get("dockerContext", "."))
    if not os.path.isfile(dockerfile):
        p(f"dockerfilePath {s.get('dockerfilePath')} does not exist")
        return None
    if context != ROOT:
        p("dockerContext must be the repository root (the Dockerfile copies the whole workspace)")
    disk = s.get("disk") or {}
    if disk.get("mountPath") != STATE:
        p(f"disk.mountPath must be {STATE} (the image's state volume)")
    if not disk.get("name"):
        p("disk.name is required")
    if not isinstance(disk.get("sizeGB"), int) or disk["sizeGB"] < 1:
        p("disk.sizeGB must be a whole number of GB, at least 1")
    env = {}
    org_prompted = False
    for v in s.get("envVars") or []:
        key = v.get("key")
        if key == "WITNESS_ORG":
            org_prompted = v.get("sync") is False and "value" not in v
            continue
        if "value" not in v or not isinstance(v["value"], str):
            p(f"envVars {key}: give a quoted string value")
            continue
        env[key] = v["value"]
    if not org_prompted:
        p("WITNESS_ORG must be `sync: false` with no value, so the operator names their own organisation")
    for forbidden in ("WITNESS_NAME", "WITNESS_URL"):
        if forbidden in env:
            p(f"{forbidden} must not be fixed here: it would be the same for every operator")
    return {
        "dockerfile": rel(dockerfile),
        "context": ".",
        "build_args": {k: env[k] for k in ("WITNESS_IMAGE_USER",) if k in env},
        "env": {k: v for k, v in env.items() if k not in ("PORT",)},
        "port": int(env["PORT"]) if env.get("PORT", "").isdigit() else None,
        "mount": disk.get("mountPath"),
        "health": s.get("healthCheckPath"),
    }


def check_fly(problems):
    try:
        doc = tomllib.load(open(FLY, "rb"))
    except (OSError, tomllib.TOMLDecodeError) as e:
        problems.append(f"deploy/fly/fly.toml: {e}")
        return None
    p = lambda msg: problems.append(f"deploy/fly/fly.toml: {msg}")  # noqa: E731
    if "app" in doc:
        p("must not name an app: `fly launch` writes each operator's own")
    for key in ("processes", "experimental"):
        if key in doc:
            p(f"[{key}] could replace the image's entrypoint, which the CI job tests")
    build = doc.get("build") or {}
    # The README copies this file to the repository root, so its paths are
    # relative to the root, which is also the build context.
    dockerfile = repo_path(build.get("dockerfile", "Dockerfile"))
    if not os.path.isfile(dockerfile):
        p(f"[build] dockerfile {build.get('dockerfile')} does not exist (paths are relative to the repository root)")
        return None
    args = {k: str(v) for k, v in (build.get("args") or {}).items()}
    env = doc.get("env") or {}
    for k, v in env.items():
        if not isinstance(v, str):
            p(f"[env] {k} must be a string")
    for forbidden in ("WITNESS_ORG", "WITNESS_NAME", "WITNESS_URL"):
        if forbidden in env:
            p(f"[env] {forbidden} must not be fixed here: it would be the same for every operator")
    mounts = doc.get("mounts")
    mounts = [mounts] if isinstance(mounts, dict) else (mounts or [])
    if len(mounts) != 1 or mounts[0].get("destination") != STATE or not mounts[0].get("source"):
        p(f"needs exactly one [[mounts]] with a source and destination = \"{STATE}\"")
    svc = doc.get("http_service") or {}
    if svc.get("force_https") is not True:
        p("[http_service] force_https must be true")
    if svc.get("auto_stop_machines") != "off":
        p("[http_service] auto_stop_machines must be \"off\": a stopped witness cosigns nothing")
    if svc.get("auto_start_machines") is not False:
        p("[http_service] auto_start_machines must be false: a Machine stopped for a snapshot or a move "
          "must stay stopped, or it cosigns after the snapshot and two copies of one key diverge")
    if not isinstance(svc.get("min_machines_running"), int) or svc["min_machines_running"] < 1:
        p("[http_service] min_machines_running must be at least 1")
    checks = svc.get("checks") or []
    if not any(c.get("path") == HEALTH and c.get("method", "get").lower() == "get" for c in checks):
        p(f"[[http_service.checks]] needs a GET {HEALTH} check")
    if mounts and os.path.isfile(FLY_README):
        readme = open(FLY_README, encoding="utf-8").read()
        if f"fly volumes create {mounts[0].get('source')} " not in readme:
            p(f"deploy/fly/README.md must create the volume this file mounts ({mounts[0].get('source')})")
        for needed in ("WITNESS_PUBKEY", "fly volumes list", "fly machine destroy"):
            if needed not in readme:
                p(f"deploy/fly/README.md must explain `{needed}`")
    return {
        "dockerfile": rel(dockerfile),
        "context": ".",
        "build_args": args,
        "env": {k: str(v) for k, v in env.items()},
        "port": svc.get("internal_port"),
        "mount": mounts[0].get("destination") if mounts else None,
        "health": HEALTH,
    }


def check():
    problems = []
    port = listen_port(problems)
    runs = {"render": check_render(problems), "fly": check_fly(problems)}
    seen = {}
    for name, run in runs.items():
        if run is None:
            continue
        if run["dockerfile"] not in seen:  # both configs build the same file: report it once
            seen[run["dockerfile"]] = image_facts(os.path.join(ROOT, run["dockerfile"]), problems)
        facts = seen[run["dockerfile"]]
        if run["port"] != port or port not in facts["expose"]:
            problems.append(f"{name}: routes to port {run['port']}; the image listens on {port} "
                            f"and exposes {facts['expose']}")
        if run["build_args"].get("WITNESS_IMAGE_USER") != ROOT_START:
            problems.append(f"{name}: build argument WITNESS_IMAGE_USER must be {ROOT_START}: the platform "
                            "mounts the state disk owned by root, and only a root start lets the entrypoint "
                            "hand it to the witness user")
        if run["env"].get("WITNESS_BEHIND_PROXY") != "1":
            problems.append(f"{name}: WITNESS_BEHIND_PROXY must be \"1\": the platform's proxy is every client's address")
        if not run["env"].get("WITNESS_COMPUTE"):
            problems.append(f"{name}: set WITNESS_COMPUTE so verifiers can score the compute provider")
    try:
        onboarding = open(ONBOARDING, encoding="utf-8").read()
        if RENDER_BUTTON not in onboarding:
            problems.append(f"{rel(ONBOARDING)}: no Deploy to Render link ({RENDER_BUTTON})")
        if "deploy/fly" not in onboarding:
            problems.append(f"{rel(ONBOARDING)}: does not point to deploy/fly")
        if "WITNESS_PUBKEY" not in onboarding:
            problems.append(f"{rel(ONBOARDING)}: does not tell operators to set WITNESS_PUBKEY after the first start")
    except OSError as e:
        problems.append(str(e))
    return runs, problems


def main(argv):
    runs, problems = check()
    if "--emit" in argv:
        which = argv[argv.index("--emit") + 1] if argv.index("--emit") + 1 < len(argv) else ""
        if which not in runs:
            print(f"--emit takes one of {sorted(runs)}", file=sys.stderr)
            return 2
        if problems or runs[which] is None:
            for p in problems:
                print("error:", p, file=sys.stderr)
            return 1
        print(json.dumps(runs[which], indent=2, sort_keys=True))
        return 0
    for p in problems:
        print("error:", p)
    print(f"render.yaml, deploy/fly/fly.toml: {len(problems)} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
