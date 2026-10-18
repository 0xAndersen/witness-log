"""The extras' version floors stay at or above the first release without a
known advisory (security sweep F10). An extra's floor is what a resolver
may pick when something else in the environment holds a dependency back,
so a floor below a fixed release admits the vulnerable one."""

from __future__ import annotations

import pathlib
import re

import pytest

PYPROJECT = pathlib.Path(__file__).resolve().parents[1] / "pyproject.toml"

# package -> first release without the advisory
FIXED = {
    "mcp": (2, 2, 0),
    "claude-agent-sdk": (0, 2, 121),
    "langchain-core": (1, 3, 3),
    "langgraph": (1, 0, 10),
    "pydantic-ai-slim": (2, 52, 0),
}


def _extras():
    """{extra: [requirement, ...]} from [project.optional-dependencies],
    parsed by hand: tomllib is 3.11+ and the bindings support 3.9."""
    text = PYPROJECT.read_text()
    section = text.split("[project.optional-dependencies]", 1)[1].split("\n[", 1)[0]
    extras, current = {}, None
    for line in section.splitlines():
        m = re.match(r"^([A-Za-z0-9_-]+)\s*=\s*\[(.*)$", line)
        if m:
            current = m.group(1)
            extras[current] = []
            line = m.group(2)
        if current is not None:
            extras[current] += re.findall(r'"([^"]+)"', line.split("#", 1)[0])
            if "]" in line.split("#", 1)[0]:
                current = None
    return extras


def _floor(req: str):
    m = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?\s*>=\s*([0-9][0-9.]*)", req)
    if not m:
        return None, None
    return m.group(1).lower(), tuple(int(x) for x in m.group(2).split("."))


def _pad(v):
    return v + (0,) * (3 - len(v))


def test_every_extra_is_parsed():
    extras = _extras()
    assert {"mcp", "langchain", "langgraph", "pydantic-ai", "claude-agent-sdk", "all-frameworks"} <= set(extras), extras
    assert all(extras[k] for k in extras), extras


@pytest.mark.parametrize("package", sorted(FIXED))
def test_floors_are_at_or_above_the_fixed_release(package):
    seen = []
    for extra, reqs in _extras().items():
        for req in reqs:
            name, floor = _floor(req)
            if name == package:
                seen.append(extra)
                assert floor is not None and _pad(floor) >= FIXED[package], (
                    f"[{extra}] {req!r} admits a release before {'.'.join(map(str, FIXED[package]))}"
                )
    assert seen, f"{package} is in no extra"
