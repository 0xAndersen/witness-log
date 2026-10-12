"""RFC 8785 conformance for ``witness_log.profiles._jcs``: the RFC's own
worked examples (§3.2.3 and Appendix B) plus the cases where Python's
``json.dumps`` differs, which is why the module exists."""

from __future__ import annotations

import json
import math

import pytest

from witness_log.profiles import _jcs


def test_rfc8785_section_3_2_3_sample():
    # RFC 8785 §3.2.3, verbatim input and expected output.
    src = (
        '{"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],'
        ' "string": "\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/",'
        ' "literals": [null, true, false]}'
    )
    want = (
        '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
        '"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}'
    )
    assert _jcs.dumps(json.loads(src)) == want
    assert _jcs.canonicalize(json.loads(src)) == want.encode("utf-8")


def test_rfc8785_key_sorting_by_utf16_code_units():
    # RFC 8785 §3.2.3 second example: the emoji (a surrogate pair, D83D..)
    # sorts before U+FB33 even though its code point is larger.
    src = {
        "€": "Euro Sign",
        "\r": "Carriage Return",
        "דּ": "Hebrew Letter Dalet With Dagesh",
        "1": "One",
        "\U0001f600": "Emoji: Grinning Face",
        "\u0080": "Control",
        "ö": "Latin Small Letter O With Diaeresis",
    }
    want = (
        '{"\\r":"Carriage Return","1":"One","\u0080":"Control","ö":"Latin Small Letter O With Diaeresis",'
        '"€":"Euro Sign","\U0001f600":"Emoji: Grinning Face","דּ":"Hebrew Letter Dalet With Dagesh"}'
    )
    assert _jcs.dumps(src) == want
    # Python's own sort (by code point) gets this wrong, which is the point.
    assert json.dumps(src, sort_keys=True, ensure_ascii=False, separators=(",", ":")) != want


@pytest.mark.parametrize(
    "value,want",
    [
        # RFC 8785 Appendix B, ES6 number serialisation samples.
        (0.0, "0"),
        (-0.0, "0"),
        (1.0, "1"),
        (5e-324, "5e-324"),
        (-5e-324, "-5e-324"),
        (1.7976931348623157e308, "1.7976931348623157e+308"),
        (9007199254740992.0, "9007199254740992"),
        (-9007199254740992.0, "-9007199254740992"),
        (295147905179352830000.0, "295147905179352830000"),
        (1e21, "1e+21"),
        (9.999999999999997e22, "9.999999999999997e+22"),
        (1e23, "1e+23"),
        (999999999999999700000.0, "999999999999999700000"),
        (0.000001, "0.000001"),
        (1e-7, "1e-7"),
        (0.1, "0.1"),
        (0.5, "0.5"),
        (1.5, "1.5"),
        (3.3333333333333335, "3.3333333333333335"),
        (333333333.3333333, "333333333.3333333"),
        (123456789012345680.0, "123456789012345680"),
        (-1.5, "-1.5"),
        (1e30, "1e+30"),
        (4.5, "4.5"),
        (0.002, "0.002"),
        (1e-27, "1e-27"),
    ],
)
def test_es6_number_serialization(value, want):
    assert _jcs.dumps(value) == want


def test_integers_pass_through_and_large_ones_become_doubles():
    assert _jcs.dumps(42) == "42"
    assert _jcs.dumps(-7) == "-7"
    assert _jcs.dumps(2**53 - 1) == "9007199254740991"
    # Beyond 2^53 the value is an IEEE double in every JCS implementation.
    assert _jcs.dumps(2**53 + 1) == "9007199254740992"
    assert _jcs.dumps(10**21) == "1e+21"


def test_where_python_json_differs():
    # Each of these is a byte-level disagreement with json.dumps(sort_keys=True).
    assert _jcs.dumps(1.0) == "1" and json.dumps(1.0) == "1.0"
    assert _jcs.dumps(1e-7) == "1e-7" and json.dumps(1e-7) == "1e-07"
    assert _jcs.dumps(1e20) == "100000000000000000000" and json.dumps(1e20) == "1e+20"
    assert _jcs.dumps("é") == '"é"' and json.dumps("é") == '"\\u00e9"'
    assert _jcs.dumps("\x7f") == '"\x7f"'  # only < 0x20 is escaped


def test_string_escapes():
    assert _jcs.dumps('a"b\\c\n\t\r\b\f\x01\x1f') == '"a\\"b\\\\c\\n\\t\\r\\b\\f\\u0001\\u001f"'
    assert _jcs.dumps("/") == '"/"'  # the solidus is not escaped


def test_rejects_what_jcs_cannot_represent():
    for bad in (math.nan, math.inf, -math.inf):
        with pytest.raises(ValueError):
            _jcs.dumps(bad)
    with pytest.raises(TypeError):
        _jcs.dumps({1: "int key"})
    with pytest.raises(TypeError):
        _jcs.dumps(b"bytes")
    with pytest.raises(TypeError):
        _jcs.dumps(object())


def test_nested_and_empty():
    assert _jcs.dumps({}) == "{}"
    assert _jcs.dumps([]) == "[]"
    assert _jcs.dumps({"b": [1, {"d": None, "c": [True, False]}], "a": ""}) == '{"a":"","b":[1,{"c":[true,false],"d":null}]}'
    assert _jcs.dumps((1, 2)) == "[1,2]"


def test_canonical_bytes_are_stable_across_insertion_order():
    a = {"total": {"value": 120.0, "currency": "USD"}, "id": "pm_1"}
    b = {"id": "pm_1", "total": {"currency": "USD", "value": 120}}
    assert _jcs.canonicalize(a) == _jcs.canonicalize(b)
