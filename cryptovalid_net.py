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
   answer is checked by signature, or public endpoints that are http-only in practice: RFC 3161 TSAs, the trusted
   lists the EU list of lists points to, Solana RPCs, the regulatory sources). Every other scheme, a URL without a host,
   a URL with white space or a control character, a non-string URL: `ValueError` naming the reason, before any I/O;
2. schemes are compared case-insensitively (RFC 3986 §3.1): `HTTPS://host` is https;
3. a loopback host (`localhost`, 127.0.0.0/8, ::1) is reached directly, never through a proxy of the environment;
   every other host goes through the environment's proxy settings exactly as urllib reads them (`*_proxy`,
   `no_proxy`). The opener is built per call, so a proxy set after the first request of the process is read too
   (`urllib.request.urlopen` builds its opener once per process);
4. a redirect is followed only to a URL the same rule accepts (urllib alone also follows a redirect to `ftp:`), and
   never from a remote host to a loopback one.
"""
import ipaddress
import urllib.parse
import urllib.request

ALLOW_HTTPS = "https"
ALLOW_HTTPS_OR_LOOPBACK_HTTP = "https|loopback-http"
ALLOW_HTTP_OR_HTTPS = "http|https"
_POLICIES = (ALLOW_HTTPS, ALLOW_HTTPS_OR_LOOPBACK_HTTP, ALLOW_HTTP_OR_HTTPS)


def is_loopback(host) -> bool:
    """True for `localhost` (any case, with or without the final dot), 127.0.0.0/8 and ::1 (with or without brackets)."""
    if not isinstance(host, str) or not host:
        return False
    h = host.strip("[]").rstrip(".").lower()
    if h == "localhost":
        return True
    try:
        return ipaddress.ip_address(h.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


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
        if is_loopback(u.hostname) and not self._loopback:
            raise ValueError("url_not_allowed: a redirect from a remote host to a loopback host")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


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
