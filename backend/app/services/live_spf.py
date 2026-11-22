"""
Live SPF evaluation (RFC 7208) for PhishIntel.

Performs the real `check_host()` algorithm against DNS: fetches the sender domain's
SPF TXT record and recursively evaluates include / redirect / a / mx / ptr / exists /
ip4 / ip6 / all with macro expansion, enforcing the 10 DNS-lookup limit and the
2 void-lookup limit.  The resolver is injected, so no network is needed in tests.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple
from urllib.parse import quote

from app.services.dns_resolver import DnsResolver, DnsTempError

MAX_DNS_LOOKUPS = 10
MAX_VOID_LOOKUPS = 2
MAX_MX_NAMES = 10
MAX_PTR_NAMES = 10

_QUALIFIER_RESULT = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}
_AMX_RE = re.compile(r"^(a|mx)(?::([^/]+))?(?:/(\d{1,2}))?(?://(\d{1,3}))?$", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)+[A-Za-z]{2,63}\.?$|^xn--[A-Za-z0-9.-]+$")


@dataclass
class SPFLiveResult:
    result: str                      # pass | fail | softfail | neutral | none | temperror | permerror
    domain: str
    sender: str
    client_ip: str
    mechanism: Optional[str] = None  # the mechanism that produced the verdict
    record: Optional[str] = None     # SPF record of the evaluated domain
    dns_lookups: int = 0
    explanation: str = ""
    trace: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return dict(self.__dict__)


class _SPFError(Exception):
    def __init__(self, result: str, msg: str):
        super().__init__(msg)
        self.result = result
        self.msg = msg


class _Context:
    def __init__(self, ip, sender: str, helo: str, resolver: DnsResolver):
        self.ip = ip
        self.sender = sender
        self.helo = helo
        self.resolver = resolver
        self.lookups = 0
        self.voids = 0
        self.trace: List[str] = []

    def count_lookup(self, what: str) -> None:
        self.lookups += 1
        if self.lookups > MAX_DNS_LOOKUPS:
            raise _SPFError("permerror", f"Exceeded {MAX_DNS_LOOKUPS} DNS-lookup limit at '{what}'.")

    def count_void(self, what: str) -> None:
        self.voids += 1
        if self.voids > MAX_VOID_LOOKUPS:
            raise _SPFError("permerror", f"Exceeded {MAX_VOID_LOOKUPS} void-lookup limit at '{what}'.")


# --------------------------------------------------------------------------- #
# Macro expansion (RFC 7208 section 7)
# --------------------------------------------------------------------------- #
_MACRO_RE = re.compile(r"%\{([slodiphcrtvSLODIPHCRTV])(\d*)(r?)([.\-+,/_=]*)\}|%%|%_|%-")


def _ip_macro_i(ip) -> str:
    if ip.version == 4:
        return str(ip)
    return ".".join(ip.exploded.replace(":", ""))


def expand_macros(spec: str, domain: str, ctx: _Context) -> str:
    local, _, sender_dom = ctx.sender.rpartition("@")
    local = local or "postmaster"

    def repl(m: re.Match) -> str:
        if m.group(0) == "%%":
            return "%"
        if m.group(0) == "%_":
            return " "
        if m.group(0) == "%-":
            return "%20"
        letter, digits, reverse, delims = m.group(1), m.group(2), m.group(3), m.group(4)
        base = {
            "s": ctx.sender, "l": local, "o": sender_dom, "d": domain,
            "i": _ip_macro_i(ctx.ip), "p": "unknown", "h": ctx.helo,
            "v": "in-addr" if ctx.ip.version == 4 else "ip6",
            "c": str(ctx.ip), "r": "unknown", "t": "0",
        }[letter.lower()]
        parts = re.split("[" + re.escape(delims or ".") + "]", base)
        if reverse:
            parts.reverse()
        if digits:
            n = int(digits)
            if n == 0:
                raise _SPFError("permerror", "Macro transformer digit 0 is invalid.")
            parts = parts[-n:]
        out = ".".join(parts)
        return quote(out, safe="") if letter.isupper() else out

    return _MACRO_RE.sub(repl, spec)


def _truncate_domain(name: str) -> str:
    name = name.rstrip(".")
    while len(name) > 253 and "." in name:
        name = name.split(".", 1)[1]
    return name


def _valid_domain(name: str) -> bool:
    return bool(name) and bool(_DOMAIN_RE.match(name))


# --------------------------------------------------------------------------- #
# Record handling
# --------------------------------------------------------------------------- #
def _fetch_spf_record(ctx: _Context, domain: str) -> Optional[str]:
    """Return the single v=spf1 record, None if there is none. Raises on permerror/temperror."""
    try:
        txts = ctx.resolver.txt(domain)
    except DnsTempError as exc:
        raise _SPFError("temperror", str(exc))
    records = [t.strip() for t in txts if re.match(r"(?i)^v=spf1(\s|$)", t.strip())]
    if len(records) > 1:
        raise _SPFError("permerror", f"Multiple SPF records published for {domain} (RFC 7208 s4.5).")
    return records[0] if records else None


def _ip_in_network(ip, net_str: str, prefix: Optional[int]) -> bool:
    try:
        addr = ipaddress.ip_address(net_str)
    except ValueError:
        return False
    if addr.version != ip.version:
        return False
    max_len = 32 if ip.version == 4 else 128
    prefix = max_len if prefix is None else prefix
    if prefix > max_len:
        raise _SPFError("permerror", f"Invalid CIDR prefix /{prefix}.")
    return ip in ipaddress.ip_network(f"{addr}/{prefix}", strict=False)


def _addresses_of(ctx: _Context, host: str) -> List[str]:
    """Forward-resolve host as A (ipv4 client) or AAAA (ipv6 client)."""
    try:
        recs = ctx.resolver.a(host) if ctx.ip.version == 4 else ctx.resolver.aaaa(host)
    except DnsTempError as exc:
        raise _SPFError("temperror", str(exc))
    if not recs:
        ctx.count_void(host)
    return recs


# --------------------------------------------------------------------------- #
# check_host
# --------------------------------------------------------------------------- #
def _check_host(ctx: _Context, domain: str, depth: int = 0) -> Tuple[str, Optional[str], Optional[str]]:
    """Returns (result, mechanism, record). Raises _SPFError for permerror/temperror."""
    if depth > MAX_DNS_LOOKUPS + 1:
        raise _SPFError("permerror", "SPF recursion too deep.")
    if not _valid_domain(domain):
        return "none", None, None

    record = _fetch_spf_record(ctx, domain)
    if record is None:
        return "none", None, None
    ctx.trace.append(f"{domain}: {record}")

    terms = record.split()[1:]
    redirect: Optional[str] = None

    for term in terms:
        low = term.lower()
        if low.startswith("redirect="):
            if redirect is not None:
                raise _SPFError("permerror", "Duplicate redirect modifier.")
            redirect = term.split("=", 1)[1]
            continue
        if low.startswith("exp=") or re.match(r"^[a-z][a-z0-9_.\-]*=", low):
            continue  # exp and unknown modifiers are ignored

        qualifier = "+"
        if term[0] in _QUALIFIER_RESULT:
            qualifier, term = term[0], term[1:]
        am = _AMX_RE.match(term)
        if am:  # a / mx with optional :domain and /v4 //v6 CIDR lengths
            name_l = am.group(1).lower()
            arg = am.group(2) or ""
            c4 = int(am.group(3)) if am.group(3) else None
            c6 = int(am.group(4)) if am.group(4) else None
        else:
            name, _, arg = term.partition(":")
            name_l = name.lower()
            c4 = c6 = None
        verdict = _QUALIFIER_RESULT[qualifier]
        mech_label = f"{qualifier if qualifier != '+' else ''}{term}"

        matched = False
        if name_l == "all":
            matched = True

        elif name_l == "ip4" or name_l == "ip6":
            net, _, plen = arg.partition("/")
            try:
                matched = _ip_in_network(ctx.ip, net, int(plen) if plen else None)
            except ValueError:
                raise _SPFError("permerror", f"Invalid {name_l} term '{term}'.")

        elif name_l in ("a", "mx"):
            ctx.count_lookup(term)
            target = _truncate_domain(expand_macros(arg, domain, ctx)) if arg else domain
            prefix = c4 if ctx.ip.version == 4 else c6
            if name_l == "a":
                matched = any(_ip_in_network(ctx.ip, addr, prefix) for addr in _addresses_of(ctx, target))
            else:
                try:
                    hosts = ctx.resolver.mx(target)
                except DnsTempError as exc:
                    raise _SPFError("temperror", str(exc))
                if not hosts:
                    ctx.count_void(target)
                if len(hosts) > MAX_MX_NAMES:
                    raise _SPFError("permerror", f"MX {target} has more than {MAX_MX_NAMES} hosts.")
                for h in hosts:
                    if any(_ip_in_network(ctx.ip, addr, prefix) for addr in _addresses_of(ctx, h)):
                        matched = True
                        break

        elif name_l == "include":
            if not arg:
                raise _SPFError("permerror", "include requires a domain.")
            ctx.count_lookup(term)
            target = _truncate_domain(expand_macros(arg, domain, ctx))
            res, _, _ = _check_host(ctx, target, depth + 1)
            if res == "none":
                raise _SPFError("permerror", f"include target '{target}' has no SPF record.")
            matched = res == "pass"

        elif name_l == "exists":
            if not arg:
                raise _SPFError("permerror", "exists requires a domain.")
            ctx.count_lookup(term)
            target = _truncate_domain(expand_macros(arg, domain, ctx))
            try:
                recs = ctx.resolver.a(target)
            except DnsTempError as exc:
                raise _SPFError("temperror", str(exc))
            if not recs:
                ctx.count_void(target)
            matched = bool(recs)

        elif name_l == "ptr":
            ctx.count_lookup(term)
            target = _truncate_domain(expand_macros(arg, domain, ctx)) if arg else domain
            try:
                names = ctx.resolver.ptr(str(ctx.ip))
            except DnsTempError as exc:
                raise _SPFError("temperror", str(exc))
            for host in names[:MAX_PTR_NAMES]:
                host_l = host.lower().rstrip(".")
                if not (host_l == target.lower() or host_l.endswith("." + target.lower())):
                    continue
                try:
                    fwd = ctx.resolver.a(host_l) if ctx.ip.version == 4 else ctx.resolver.aaaa(host_l)
                except DnsTempError:
                    continue
                if any(_ip_in_network(ctx.ip, a, None) for a in fwd):
                    matched = True
                    break
        else:
            raise _SPFError("permerror", f"Unknown SPF mechanism '{name}'.")

        if matched:
            ctx.trace.append(f"  matched '{mech_label}' -> {verdict}")
            return verdict, mech_label, record

    if redirect is not None:
        ctx.count_lookup(f"redirect={redirect}")
        target = _truncate_domain(expand_macros(redirect, domain, ctx))
        res, mech, rec = _check_host(ctx, target, depth + 1)
        if res == "none":
            raise _SPFError("permerror", f"redirect target '{target}' has no SPF record.")
        return res, mech, rec

    return "neutral", None, record


def check_spf(
    client_ip: str,
    mail_from: str,
    helo: Optional[str],
    resolver: DnsResolver,
) -> SPFLiveResult:
    """
    Evaluate SPF for (client_ip, MAIL FROM, HELO) against live DNS.

    `mail_from` may be empty / '<>' (bounce): the HELO identity is then used, as RFC 7208 s2.4 requires.
    """
    try:
        ip = ipaddress.ip_address(client_ip.strip())
    except ValueError:
        return SPFLiveResult("permerror", "", mail_from or "", client_ip, explanation=f"Invalid client IP '{client_ip}'.")
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped

    sender = (mail_from or "").strip().strip("<>").strip()
    helo = (helo or "").strip().rstrip(".")
    if not sender:
        if not helo:
            return SPFLiveResult("none", "", "", str(ip), explanation="No MAIL FROM and no HELO identity available.")
        sender = f"postmaster@{helo}"
    if "@" not in sender:
        sender = f"postmaster@{sender}"
    domain = sender.rpartition("@")[2].lower().rstrip(".")

    ctx = _Context(ip, sender, helo or domain, resolver)
    try:
        result, mech, record = _check_host(ctx, domain)
        if result == "none":
            expl = f"Domain {domain} publishes no SPF record."
        elif mech:
            expl = f"{ip} evaluated against SPF of {domain}: matched '{mech}' -> {result}."
        else:
            expl = f"{ip} evaluated against SPF of {domain}: no mechanism matched -> {result}."
        return SPFLiveResult(result, domain, sender, str(ip), mech, record, ctx.lookups, expl, ctx.trace)
    except _SPFError as err:
        return SPFLiveResult(err.result, domain, sender, str(ip), None, None, ctx.lookups,
                             f"SPF {err.result}: {err.msg}", ctx.trace)
