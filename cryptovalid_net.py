#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""Outbound HTTP(S) of every module of this repository that opens a URL: one closed rule (15/11/2026).

Until 0.24.0 each module called `urllib.request.urlopen` on its own, and two defects followed (measured 15/11/2026):

- **scheme**: five call sites (TSA client, NetHSM backend, EU trusted lists, Solana pruning probe, witness client)
  passed any URL to urlopen, which also opens `file:`, `ftp:` and `data:` URLs; the AWS KMS endpoint check let
  `file://localhost/...` through (scheme not https, but host loopback);
- **proxy**: with `HTTP_PROXY` / `HTTPS_PROXY` in the environment, a loopback endpoint (a local Vault, a KMS emulator,
  a TSA or witness on 127.0.0.1) was asked through the proxy, which cannot reach this host's loopback and receives the
  request (a Vault token, a SigV4-signed call) instead.

The rule, closed by construction:

1. the caller names the schemes it accepts, from `ALLOW_HTTPS` (https only), `ALLOW_HTTPS_OR_LOOPBACK_HTTP` (plain
   http only towards a loopback host: credentials must not travel in clear) or `ALLOW_HTTP_OR_HTTPS` (endpoints whose
   answer is checked by signature, or public endpoints that are http-only in practice: RFC 3161 TSAs, Solana RPCs, the
   regulatory sources; the trusted lists the EU list of lists points to are https only since SPEC §22 rule 6). Every other scheme, a URL without a host,
   a URL with white space or a control character, a non-string URL: `ValueError` naming the reason, before any I/O;
2. schemes are compared case-insensitively (RFC 3986 §3.1): `HTTPS://host` is https;
3. a loopback host (`localhost`, 127.0.0.0/8, ::1) is reached directly, never through a proxy of the environment;
   every other host goes through the environment's proxy settings exactly as urllib reads them (`*_proxy`,
   `no_proxy`). The opener is built per call, so a proxy set after the first request of the process is read too
   (`urllib.request.urlopen` builds its opener once per process);
4. a redirect is followed only to a URL the same rule accepts (urllib alone also follows a redirect to `ftp:`), and
   never from a host that is not loopback to a loopback, unspecified or link-local address (rule 5 says how the
   address is read), judged at every hop on the host of the request being redirected;
5. (SPEC v0.12 §20 rule 1, 19/11/2026) a host is judged as the ADDRESS the system would connect to, not as a string:
   an IP literal in any form `inet_aton` reads (`127.1`, `2130706433`, `0x7f000001`, `0177.0.0.1`) or `inet_pton`
   reads as IPv6, an IPv4-mapped IPv6 address by the IPv4 address inside it, and, for the target of a redirect, a name by
   every address `getaddrinfo` gives for it; a host with a percent sign (`%31%32%37.0.0.1`, which urllib decodes to 127.0.0.1
   before it connects; the "%25" zone of an IPv6 literal too, out of the URI syntax since RFC 9844) is refused. Until
   0.26.0 the host was compared as text, and a redirect from a remote
   host to `http://127.1/`, `http://0.0.0.0/` or `http://[::ffff:127.0.0.1]/` was followed (measured 19/11/2026);
6. (SPEC v0.12 §20 rule 2) a redirect to another origin (scheme, host, port) is refused when the request carries a
   header outside `FORWARDED_ACROSS_ORIGINS`, a closed list of headers that name no credential: urllib copies every
   header of the request to the redirected one, so an `Authorization`, `X-Vault-Token` or `X-Amz-Security-Token`
   went to the host the answer named (measured 19/11/2026). Refused, not stripped: the caller learns that its
   endpoint redirects elsewhere. `Proxy-Authorization` is the one exception, and it is never copied to a redirected
   request at all: it "applies only to the next inbound proxy" (RFC 9110 §11.7.2), urllib's proxy handler puts it on
   a request that goes through a proxy with credentials and puts it again on the redirected one when that goes
   through the proxy too; copied by the redirect, it reached a host of `no_proxy` directly.

7. (0.29.1) a URL with credentials before the host (`user:password@host`) is refused, and the refusal does not repeat
   it: urllib never sent them (it looked the whole of it up as a host name), the callers repeated the URL in their
   errors and wrote it into timestamp records. `url_for_record` gives the URL a record may carry: scheme, host, port
   and path, without the query (an API key in `?key=` would be sealed with the evidence) and the fragment.

Not closed here, stated: a name is resolved when the redirect is judged and again when the connection is made (an
answer that changes in between is not seen), and when the name does not resolve here the redirect is left to urllib
(through a proxy of the environment the proxy resolves it; without one the connection fails on the same lookup).
"""
import ipaddress
import socket
import urllib.parse
import urllib.request

ALLOW_HTTPS = "https"
ALLOW_HTTPS_OR_LOOPBACK_HTTP = "https|loopback-http"
ALLOW_HTTP_OR_HTTPS = "http|https"
_POLICIES = (ALLOW_HTTPS, ALLOW_HTTPS_OR_LOOPBACK_HTTP, ALLOW_HTTP_OR_HTTPS)


# Headers a redirect to another origin may carry (rule 6): they describe the request, none of them is a credential.
FORWARDED_ACROSS_ORIGINS = frozenset({"accept", "accept-encoding", "accept-language", "content-length", "content-type",
                                      "user-agent"})
_DEFAULT_PORT = {"http": 80, "https": 443}


def _address(host):
    """The IP address a host string IS, or None when it is a name. Zone identifiers are dropped; the IPv4 forms of
    inet_aton (one to four parts, each decimal, octal or hexadecimal) are read as the system reads them; an IPv4-mapped
    IPv6 address is the IPv4 address inside it."""
    if not isinstance(host, str) or not host:
        return None
    h = host.strip("[]").split("%", 1)[0]
    if not h.isascii():                       # the resolver is given the IDNA form: fullwidth digits become ASCII ones
        try:
            h = h.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    if not h or any(c.isspace() for c in h):  # inet_aton stops at white space and reads what came before it
        return None
    try:                                      # the system's own readers, the ones a connection uses: `ipaddress` of
        if ":" in h:                          # Python before 3.9.5 read "0177.0.0.1" as 177.0.0.1, inet_aton as 127.0.0.1
            a = ipaddress.IPv6Address(socket.inet_pton(socket.AF_INET6, h))
        else:
            a = ipaddress.IPv4Address(socket.inet_aton(h))
    except (OSError, ValueError, UnicodeError):
        return None
    return a.ipv4_mapped or a if a.version == 6 else a


def _kind(a) -> str:
    """"loopback", "unspecified", "link-local" or "other" for an address of _address."""
    if a.is_loopback:
        return "loopback"
    if a.is_unspecified:
        return "unspecified"
    if a.is_link_local:
        return "link-local"
    return "other"


def is_loopback(host) -> bool:
    """True for `localhost` (any case, with or without the final dot) and for an IP literal, in any form of rule 5,
    inside 127.0.0.0/8 or equal to ::1 (with or without brackets)."""
    if not isinstance(host, str) or not host:
        return False
    h = host.strip("[]").rstrip(".").lower()
    if h == "localhost":
        return True
    a = _address(h)
    return a is not None and a.is_loopback


def _redirect_target_kinds(host) -> set:
    """The kinds (see _kind) of every address a redirect to `host` could reach: the literal's own, or one per address
    getaddrinfo gives for a name; empty when the name does not resolve here (module docstring, "Not closed here")."""
    if is_loopback(host):
        return {"loopback"}
    a = _address(host)
    if a is not None:
        return {_kind(a)}
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (OSError, UnicodeError):
        return set()
    kinds = set()
    for info in infos:
        got = _address(info[4][0])
        kinds.add(_kind(got) if got is not None else "other")
    return kinds


def _origin(u: urllib.parse.SplitResult):
    scheme = u.scheme.lower()
    a = _address(u.hostname)
    return scheme, (str(a) if a is not None else (u.hostname or "").rstrip(".").lower()), u.port or _DEFAULT_PORT.get(scheme)


def url_for_record(url) -> str:
    """The URL as a record or a message may carry it: scheme, host, port and path. Credentials before the host, the
    query and the fragment are left out (an API key in `?key=...` works with a TSA and would be sealed with the evidence);
    "<url>" for what is not a URL string."""
    try:
        u = urllib.parse.urlsplit(url)
        netloc = u.netloc.rpartition("@")[2]
        return urllib.parse.urlunsplit((u.scheme, netloc, u.path, "", "")) if u.scheme and netloc else "<url>"
    except (ValueError, TypeError, AttributeError):
        return "<url>"


def check_url(url, allow: str) -> urllib.parse.SplitResult:
    """The URL split, or ValueError("url_not_allowed: <reason>") if the rule of this module refuses it."""
    if allow not in _POLICIES:
        raise ValueError(f"url policy {allow!r} is not one of {_POLICIES}")
    if not isinstance(url, str):
        raise ValueError(f"url_not_allowed: a URL is a string, not {type(url).__name__}")
    if any(c.isspace() or ord(c) < 0x20 or ord(c) == 0x7F for c in url):
        raise ValueError("url_not_allowed: white space or a control character in the URL")
    try:
        u = urllib.parse.urlsplit(url)
        host = u.hostname
        u.port   # noqa: B018 — a port that is not a number raises here, not inside urllib
    except ValueError as e:
        raise ValueError(f"url_not_allowed: {e}") from None
    scheme = u.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"url_not_allowed: scheme {u.scheme[:16]!r} (only https"
                         + (" or http" if allow == ALLOW_HTTP_OR_HTTPS else
                            " or http to a loopback host" if allow == ALLOW_HTTPS_OR_LOOPBACK_HTTP else "") + ")")
    if not host:
        raise ValueError("url_not_allowed: no host")
    if "@" in u.netloc:   # 0.29.1: urllib never sent them (it looked up "user:password@host" as a name), and the callers
        # repeated the URL in their error and wrote it into the timestamp record of an archive. Never repeated here.
        raise ValueError("url_not_allowed: credentials in the URL (user:password@host); this client does not send "
                         "them, and a URL is written into records and error messages")
    if "%" in host:   # SPEC v0.12 §20 rule 1: urllib decodes %XX in the host before it connects (Request.host is unquoted);
        # no zone either: RFC 9844 (2025) obsoleted RFC 6874 and with it the "%25" zone of an IPv6 literal in a URI
        raise ValueError("url_not_allowed: a percent sign in the host (urllib decodes %XX before it connects: the address "
                         "it reaches is not the one written)")
    if scheme == "http" and allow == ALLOW_HTTPS:
        raise ValueError("url_not_allowed: plain http (https only)")
    if scheme == "http" and allow == ALLOW_HTTPS_OR_LOOPBACK_HTTP and not is_loopback(host):
        raise ValueError("url_not_allowed: plain http to a host that is not loopback (credentials would travel in clear)")
    return u


class _Redirects(urllib.request.HTTPRedirectHandler):
    def __init__(self, allow: str, loopback: bool):
        super().__init__()
        self._allow, self._loopback = allow, loopback

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        u = check_url(urllib.parse.urljoin(req.full_url, newurl), self._allow)
        here = urllib.parse.urlsplit(req.full_url)
        if not (self._loopback and is_loopback(here.hostname)):   # rules 4 and 5: judged at this hop, on the address
            kinds = _redirect_target_kinds(u.hostname)
            for kind in ("loopback", "unspecified", "link-local"):
                if kind in kinds:
                    raise ValueError(f"url_not_allowed: a redirect from a remote host to a {kind} "
                                     + ("host" if kind == "loopback" else "address"))
        if _origin(u) != _origin(here):           # rule 6
            kept = sorted(k for k in req.headers                       # req.headers: the ones urllib copies
                          if k.lower() not in FORWARDED_ACROSS_ORIGINS and k.lower() != "proxy-authorization")
            if kept:
                raise ValueError("url_not_allowed: a redirect to another origin for a request that carries "
                                 + ", ".join(kept)[:120] + " (a credential stays with the origin it was given to)")
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None:                       # for the proxy alone (RFC 9110 §11.7.2): the proxy handler adds it again
            for k in [k for k in new.headers if k.lower() == "proxy-authorization"]:
                del new.headers[k]
        return new


# SPEC v0.13 §21 rule 6: a body read from the network is bounded. Until 0.27.0 seven modules read a response whole
# (`read()`, `json.load`), however long it was. The largest document this package fetches is a trusted list of the EU
# LOTL: measured on 2026-11-20, the 31 lists it points to and the LOTL itself are at most 5,367,120 bytes.
MAX_RESPONSE_BYTES = 64 * 1024 * 1024


def read_body(resp, limit: int = MAX_RESPONSE_BYTES) -> bytes:
    """The body of an HTTP response, at most `limit` bytes; ValueError("response_too_large: ...") when there are more.
    Reads `limit` + 1 bytes at most, whatever Content-Length says."""
    chunks, n = [], 0
    while n <= limit:
        b = resp.read(min(1 << 20, limit + 1 - n))
        if not b:
            break
        chunks.append(b)
        n += len(b)
    if n > limit:
        raise ValueError(f"response_too_large: the response exceeds {limit} bytes")
    return b"".join(chunks)


def _open(req, timeout, loopback: bool, allow: str):
    """The single place that does I/O (tests replace it to answer without a network)."""
    handlers = [_Redirects(allow, loopback)]
    if loopback:
        handlers.append(urllib.request.ProxyHandler({}))   # the loopback of THIS host: never through a proxy
    return urllib.request.build_opener(*handlers).open(req, timeout=timeout)


def open_url(req, timeout, allow: str):
    """`urllib.request.urlopen(req, timeout=timeout)` under the rule of this module. `req`: a URL string or a
    `urllib.request.Request`. Raises ValueError("url_not_allowed: ...") before any I/O when the rule refuses the URL;
    otherwise the errors of urllib (HTTPError, URLError, OSError) as they are."""
    url = req.full_url if isinstance(req, urllib.request.Request) else req
    u = check_url(url, allow)
    return _open(req, timeout, is_loopback(u.hostname), allow)
