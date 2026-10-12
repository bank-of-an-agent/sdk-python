"""WHATWG URL serialization for ``http``/``https`` URLs.

RFC 9421 ``@target-uri`` must be byte-identical on the signer and the verifier.
The TypeScript reference computes it as ``new URL(url).toString()``; this module
reproduces that serialization for the special schemes ``http`` and ``https``:
scheme and host lowercased, default ports dropped, an empty path becomes ``/``,
dot segments are resolved, backslashes are treated as slashes, and characters
outside the WHATWG percent-encode sets are percent-encoded (existing escapes
are preserved as-is).
"""

from __future__ import annotations

import ipaddress
import re

__all__ = ["whatwg_url"]

_DEFAULT_PORTS = {"http": 80, "https": 443}

# Percent-encode sets (WHATWG URL Standard, section 1.3), on top of the C0
# control set (U+0000 to U+001F and everything above U+007E).
_FRAGMENT_SET = frozenset(' "<>`')
_SPECIAL_QUERY_SET = frozenset(" \"#<>'")
_PATH_SET = frozenset(' "#<>?`{}^')
_USERINFO_SET = _PATH_SET | frozenset("/:;=@[\\]|")

_TAB_OR_NEWLINE = re.compile(r"[\t\n\r]")
_SINGLE_DOT = {".", "%2e"}
_DOUBLE_DOT = {"..", ".%2e", "%2e.", "%2e%2e"}


def _percent_encode(value: str, encode_set: frozenset[str]) -> str:
    out: list[str] = []
    for char in value:
        if ord(char) < 0x20 or ord(char) > 0x7E or char in encode_set:
            out.extend(f"%{byte:02X}" for byte in char.encode("utf-8", "surrogatepass"))
        else:
            out.append(char)
    return "".join(out)


def _serialize_host(raw_host: str) -> str:
    if raw_host.startswith("["):
        if not raw_host.endswith("]"):
            raise ValueError(f"Invalid IPv6 host: {raw_host!r}")
        return "[" + ipaddress.IPv6Address(raw_host[1:-1]).compressed + "]"
    if not raw_host:
        raise ValueError("URL has an empty host")
    if raw_host.isascii():
        return raw_host.lower()
    # Non-ASCII hostnames: IDNA (Python's built-in IDNA 2003 codec). Clients of the
    # Agent Bank API only ever sign URLs that httpx already encoded to ASCII.
    return raw_host.encode("idna").decode("ascii").lower()


def _serialize_path(raw_path: str) -> str:
    raw_path = raw_path.replace("\\", "/")
    parts = raw_path[1:].split("/") if raw_path.startswith("/") else raw_path.split("/")
    segments: list[str] = []
    last = len(parts) - 1
    for index, part in enumerate(parts):
        lowered = part.lower()
        if lowered in _DOUBLE_DOT:
            if segments:
                segments.pop()
            if index == last:
                segments.append("")
        elif lowered in _SINGLE_DOT:
            if index == last:
                segments.append("")
        else:
            segments.append(_percent_encode(part, _PATH_SET))
    return "/" + "/".join(segments)


def whatwg_url(url: str) -> str:
    """Serialize an absolute ``http``/``https`` URL like ``new URL(url).toString()``.

    Args:
        url: Absolute URL string.

    Returns:
        The WHATWG serialization of ``url``.

    Raises:
        ValueError: If the URL is not an absolute ``http``/``https`` URL or has an
            invalid host or port.
    """
    value = _TAB_OR_NEWLINE.sub("", url).strip("".join(chr(c) for c in range(0x21)))
    scheme, sep, rest = value.partition(":")
    scheme = scheme.lower()
    if not sep or scheme not in _DEFAULT_PORTS:
        raise ValueError(f"Only absolute http(s) URLs can be signed, got {url!r}")

    rest = rest.lstrip("/\\")
    end = len(rest)
    for delimiter in "/\\?#":
        found = rest.find(delimiter)
        if found != -1:
            end = min(end, found)
    authority, remainder = rest[:end], rest[end:]

    userinfo = ""
    if "@" in authority:
        raw_userinfo, authority = authority.rsplit("@", 1)
        username, _, password = raw_userinfo.partition(":")
        username = _percent_encode(username, _USERINFO_SET)
        password = _percent_encode(password, _USERINFO_SET)
        if username or password:
            userinfo = username + (":" + password if password else "") + "@"

    port_text = ""
    if authority.startswith("["):
        bracket = authority.find("]")
        host_text, after = authority[: bracket + 1], authority[bracket + 1 :]
        if after.startswith(":"):
            port_text = after[1:]
        elif after:
            raise ValueError(f"Invalid host in {url!r}")
    else:
        host_text, _, port_text = authority.partition(":")
    host = _serialize_host(host_text)

    port = ""
    if port_text:
        if not port_text.isdigit() or int(port_text) > 65535:
            raise ValueError(f"Invalid port in {url!r}")
        if int(port_text) != _DEFAULT_PORTS[scheme]:
            port = f":{int(port_text)}"

    fragment: str | None = None
    if "#" in remainder:
        remainder, fragment = remainder.split("#", 1)
    query: str | None = None
    if "?" in remainder:
        remainder, query = remainder.split("?", 1)

    out = f"{scheme}://{userinfo}{host}{port}{_serialize_path(remainder)}"
    if query is not None:
        out += "?" + _percent_encode(query, _SPECIAL_QUERY_SET)
    if fragment is not None:
        out += "#" + _percent_encode(fragment, _FRAGMENT_SET)
    return out
