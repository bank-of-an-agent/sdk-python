"""Canonical JSON and the WHATWG URL serializer.

Expected values were produced by Node.js 22 (``JSON.stringify``,
``String(number)`` and ``new URL(url).toString()``), which is what the
TypeScript reference implementation relies on.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

import pytest

from agentbank._url import whatwg_url
from agentbank.canonical import (
    canonical_json,
    canonical_keccak,
    canonical_sha256,
    js_number_to_string,
    js_string_literal,
    to_jsonable,
)
from agentbank.http_signatures import target_uri
from agentbank.models import Money, PolicyDocument

NODE_URLS = [
    ("https://api.example.test/v1/payments", "https://api.example.test/v1/payments"),
    ("https://API.Example.TEST/v1/payments", "https://api.example.test/v1/payments"),
    ("https://api.example.test:443/v1/payments", "https://api.example.test/v1/payments"),
    ("http://api.example.test:80/v1/payments", "http://api.example.test/v1/payments"),
    (
        "http://localhost:8080/v1/accounts/acct_1/balances?x=1",
        "http://localhost:8080/v1/accounts/acct_1/balances?x=1",
    ),
    ("https://api.example.test", "https://api.example.test/"),
    ("https://api.example.test?x=1", "https://api.example.test/?x=1"),
    ("https://api.example.test/v1/a b", "https://api.example.test/v1/a%20b"),
    ("https://api.example.test/v1/a%20b", "https://api.example.test/v1/a%20b"),
    ("https://api.example.test/v1/%7Efoo/~bar", "https://api.example.test/v1/%7Efoo/~bar"),
    (
        'https://api.example.test/v1/x?q=a b&r="quoted"',
        "https://api.example.test/v1/x?q=a%20b&r=%22quoted%22",
    ),
    ("https://api.example.test/v1/x?q=it's", "https://api.example.test/v1/x?q=it%27s"),
    ("https://api.example.test/v1/x?", "https://api.example.test/v1/x?"),
    ("https://api.example.test/v1/x#frag", "https://api.example.test/v1/x#frag"),
    ("https://api.example.test/v1/./a/../b", "https://api.example.test/v1/b"),
    ("https://api.example.test/v1/%2e/a/%2E%2E/b", "https://api.example.test/v1/b"),
    (
        "https://api.example.test/v1/{id}/^caret/`tick`/|pipe|",
        "https://api.example.test/v1/%7Bid%7D/%5Ecaret/%60tick%60/|pipe|",
    ),
    ("https://api.example.test/v1/ü/x?q=ü", "https://api.example.test/v1/%C3%BC/x?q=%C3%BC"),
    ("https://bücher.example/v1", "https://xn--bcher-kva.example/v1"),
    ("https://user:pa ss@api.example.test/v1", "https://user:pa%20ss@api.example.test/v1"),
    ("https://api.example.test:08443/v1", "https://api.example.test:8443/v1"),
    ("https://[2001:DB8::1]:8443/v1", "https://[2001:db8::1]:8443/v1"),
    ("https://127.0.0.1:8443/v1", "https://127.0.0.1:8443/v1"),
    ("https://api.example.test/v1/a\\b", "https://api.example.test/v1/a/b"),
    (
        "https://api.example.test/v1?a=%7B%7D&b={}&c=[]",
        "https://api.example.test/v1?a=%7B%7D&b={}&c=[]",
    ),
    ("https://api.example.test/v1/<x>", "https://api.example.test/v1/%3Cx%3E"),
    ("https://api.example.test/v1/a;b=c/d:e@f", "https://api.example.test/v1/a;b=c/d:e@f"),
    ("HTTPS://api.example.test/V1/Payments", "https://api.example.test/V1/Payments"),
    ("https://api.example.test./v1", "https://api.example.test./v1"),
    ("https://api.example.test//double//slash", "https://api.example.test//double//slash"),
    ("https://api.example.test/v1/x?q=%zz&r=%", "https://api.example.test/v1/x?q=%zz&r=%"),
    ("https://api.example.test/a/b/..", "https://api.example.test/a/"),
    ("https://api.example.test/a/b/.", "https://api.example.test/a/b/"),
    ("  https://api.example.test/v1\t/x\n ", "https://api.example.test/v1/x"),
    ("https://:@api.example.test/v1", "https://api.example.test/v1"),
    ("https://user@api.example.test/v1", "https://user@api.example.test/v1"),
    ("https:///nohost", "https://nohost/"),
]

NODE_NUMBERS: list[tuple[float, str]] = [
    (0.0, "0"),
    (-0.0, "0"),
    (1.0, "1"),
    (-1.0, "-1"),
    (1.5, "1.5"),
    (0.1, "0.1"),
    (1e21, "1e+21"),
    (1e20, "100000000000000000000"),
    (123456789012345680000.0, "123456789012345680000"),
    (1e-7, "1e-7"),
    (1.5e-7, "1.5e-7"),
    (0.000001, "0.000001"),
    (1.7976931348623157e308, "1.7976931348623157e+308"),
    (5e-324, "5e-324"),
    (9007199254740992.0, "9007199254740992"),
    (-9007199254740991.0, "-9007199254740991"),
    (100.0, "100"),
    (1e300, "1e+300"),
    (0.1 + 0.2, "0.30000000000000004"),
    (123.456, "123.456"),
    (1e6, "1000000"),
    (1.23e-5, "0.0000123"),
    (12345678.9, "12345678.9"),
]

NODE_STRINGS: list[tuple[str, str]] = [
    ("\x00\x1f\x7f", '"\\u0000\\u001f\x7f"'),
    ('\b\f\n\r\t"\\/', '"\\b\\f\\n\\r\\t\\"\\\\/"'),
    (chr(0x2028) + chr(0x2029), '"' + chr(0x2028) + chr(0x2029) + '"'),
    ("\ud800", '"\\ud800"'),
    ("a\udc00b", '"a\\udc00b"'),
    ("\U0001f600", '"\U0001f600"'),
    (chr(0xD83D) + chr(0xDE00), '"\U0001f600"'),  # surrogate pair, as in UTF-16
    ("é", '"é"'),
    ("<script>", '"<script>"'),
]


@pytest.mark.parametrize(("url", "expected"), NODE_URLS)
def test_whatwg_url_matches_node(url: str, expected: str) -> None:
    assert whatwg_url(url) == expected
    assert target_uri(url) == expected


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.test/x",  # valid WHATWG URL, but only http(s) requests are signed
        "example.test/x",
        "https://example.test:99999/x",
        "https://example.test:12ab/x",
        "https://[::1/x",
        "https://[::1]junk/x",
        "https://[not-ipv6]/x",
        "https://:8080/x",
    ],
)
def test_whatwg_url_rejects_unsupported(url: str) -> None:
    with pytest.raises(ValueError, match=r".+"):
        whatwg_url(url)


@pytest.mark.parametrize(("value", "expected"), NODE_NUMBERS)
def test_js_number_formatting(value: float, expected: str) -> None:
    assert js_number_to_string(value) == expected
    assert canonical_json(value) == expected


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_numbers_are_rejected(value: float) -> None:
    with pytest.raises(ValueError, match="non-finite"):
        canonical_json(value)


@pytest.mark.parametrize(("value", "expected"), NODE_STRINGS)
def test_js_string_escaping(value: str, expected: str) -> None:
    assert js_string_literal(value) == expected


def test_vector_shape_and_key_order() -> None:
    value = {"b": 1, "a": [2, {"d": None, "c": "x"}], "e": "ü"}
    assert canonical_json(value) == '{"a":[2,{"c":"x","d":null}],"b":1,"e":"ü"}'


def test_keys_sort_by_utf16_code_units_like_javascript() -> None:
    # U+FFFF sorts after U+1F600 by code point, but before it in UTF-16 (0xD83D < 0xFFFF).
    high, emoji = chr(0xFFFF), chr(0x1F600)
    value = {high: 1, emoji: 2, "Z": 3, "a": 4, "": 5}
    assert canonical_json(value) == '{"":5,"Z":3,"a":4,"' + emoji + '":2,"' + high + '":1}'


def test_integers_beyond_the_safe_range_render_as_strings() -> None:
    assert canonical_json(2**53 - 1) == "9007199254740991"
    assert canonical_json(-(2**53 - 1)) == "-9007199254740991"
    assert canonical_json(2**53) == '"9007199254740992"'
    assert canonical_json({"max": 10**19}) == '{"max":"10000000000000000000"}'


def test_booleans_and_nested_lists() -> None:
    assert canonical_json([True, False, None, (1, 2)]) == "[true,false,null,[1,2]]"


def test_decimals_and_datetimes() -> None:
    assert canonical_json(Decimal("12.50")) == '"12.50"'
    assert canonical_json(Decimal("1E+2")) == '"100"'
    when = datetime(2026, 10, 11, 14, 0, 0, 123456, tzinfo=timezone(timedelta(hours=2)))
    assert canonical_json(when) == '"2026-10-11T12:00:00.123Z"'


def test_pydantic_models_drop_none_and_use_aliases() -> None:
    assert canonical_json(Money(amount="1.00", asset="USDC")) == '{"amount":"1.00","asset":"USDC"}'
    policy = PolicyDocument.model_validate({"$schema": "agentbank.policy.v1", "limits": {}})
    assert canonical_json(policy) == (
        '{"$schema":"agentbank.policy.v1","asset":"USDC","counterparties":{"mode":"open"},'
        '"limits":{}}'
    )


@pytest.mark.parametrize(
    ("value", "error"),
    [
        ({1: "x"}, TypeError),
        ({"x"}, TypeError),
        (b"bytes", TypeError),
        (object(), TypeError),
        (datetime(2026, 1, 1), ValueError),
        (Decimal("NaN"), ValueError),
    ],
)
def test_unsupported_values(value: Any, error: type[Exception]) -> None:
    with pytest.raises(error):
        canonical_json(value)


def test_unsupported_value_inside_plain_json_is_rejected() -> None:
    from agentbank.canonical import _serialize

    with pytest.raises(TypeError, match="unsupported"):
        _serialize(object())


def test_to_jsonable_passthrough_and_hashes() -> None:
    assert to_jsonable({"a": (1, Decimal("2"))}) == {"a": [1, "2"]}
    assert canonical_sha256({"a": 1}) == (
        "0x015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862"
    )
    assert canonical_keccak({"a": 1, "b": 2}) == canonical_keccak({"b": 2, "a": 1})
