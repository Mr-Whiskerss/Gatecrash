"""gatecrash - command line entry point."""
from __future__ import annotations

import argparse
import logging
import os
import sys
import textwrap
from typing import Dict, List, Optional
from urllib.parse import urlsplit

from . import checks as check_registry
from . import loaders, report
from .engine import EngineConfig
from .models import DESTRUCTIVE_METHODS, SEVERITY_ORDER, Endpoint, set_redaction
from .scan import adopt_collection_credentials, load_identities, run_scan

VERSION = "1.1.0"

BANNER = r"""
             _                          _
  __ _  __ _| |_ ___  ___ _ __ __ _ ___| |__     API security testing
 / _` |/ _` | __/ _ \/ __| '__/ _` / __| '_ \    for authorised engagements
| (_| | (_| | ||  __/ (__| | | (_| \__ \ | | |
 \__, |\__,_|\__\___|\___|_|  \__,_|___/_| |_|   v%s
 |___/
""".lstrip("\n")

IDENTITY_TEMPLATE = """\
# gatecrash identity profiles
#
# Each identity is a persona the scanner will test as. Two or more identities of
# equal privilege unlock the cross-user authorisation checks (BOLA/BFLA) - these
# are the findings that actually matter on an API engagement.
#
# Tokens can be read from the environment so this file is safe to keep with the
# engagement notes:  Authorization: "Bearer ${USER_A_TOKEN}"

# Hosts this scan is authorised to touch. Requests to anything else are refused.
scope:
  - api.example.com
  # - "*.staging.example.com"

# Which identity the scan baselines as. For API5 coverage make this the most
# privileged identity, so the scan can walk downward from it.
primary: admin

identities:
  # An admin unlocks API5 (Broken Function Level Authorization). Without a
  # privilege gradient the scan can only guess which routes are meant to be
  # restricted, from their path - and it will say so in the report.
  # Set `primary: admin` above so the scan baselines as the privileged caller.
  - name: admin
    role: admin                # or an explicit number: privilege: 3
    description: Administrator - enables function level authorisation testing
    headers:
      Authorization: "Bearer ${ADMIN_TOKEN}"

  - name: userA
    role: user
    description: Standard user, tenant 1
    headers:
      Authorization: "Bearer ${USER_A_TOKEN}"
    # Object identifiers this user legitimately owns. Supplying these turns
    # BOLA findings from "probable" into "firm", and stops the scanner
    # mistaking a user's own object for someone else's.
    owns:
      - "1001"

  - name: userB
    role: user
    description: Second standard user, tenant 2 - the BOLA victim/attacker pair
    headers:
      Authorization: "Bearer ${USER_B_TOKEN}"
    owns:
      - "1002"

  # An anonymous identity is added automatically if you do not declare one.
  - name: anonymous
    role: anonymous
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gatecrash",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Walk in behind a legitimate user and see what opens. Point it at a "
                    "collection and a target at the start of an API engagement; get "
                    "findings with reproducible evidence.",
        epilog=textwrap.dedent("""\
            examples:
              gatecrash init > identities.yaml
              gatecrash scan -c api.postman_collection.json -e prod.postman_environment.json \\
                          --target https://api.example.com -i identities.yaml -o ./out
              gatecrash scan -c openapi.yaml --target https://api.example.com --profile aggressive
              gatecrash scan --url https://api.example.com/v1/users --token "$TOKEN" --profile passive
              gatecrash checks
        """),
    )
    parser.add_argument("--version", action="version", version=f"gatecrash {VERSION}")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="run a scan (default command)")
    _add_scan_args(scan)

    sub.add_parser("checks", help="list every check and the profile it runs in")
    sub.add_parser("init", help="print a starter identities.yaml to stdout")

    _add_scan_args(parser)          # allow `gatecrash -c file.json ...` with no subcommand
    return parser


def _add_scan_args(p: argparse.ArgumentParser) -> None:
    src = p.add_argument_group("inputs")
    src.add_argument("-c", "--collection", action="append", default=[], metavar="FILE",
                     help="Postman collection, OpenAPI/Swagger spec, or endpoint list "
                          "(repeatable; format is auto-detected)")
    src.add_argument("-e", "--env", metavar="FILE",
                     help="Postman environment file supplying {{variables}}")
    src.add_argument("--url", action="append", default=[], metavar="URL",
                     help="test a single URL (repeatable)")
    src.add_argument("-X", "--method", default="GET",
                     help="HTTP method for --url (default: GET)")
    src.add_argument("--target", metavar="URL",
                     help="base URL of the system under test; rebases every endpoint onto "
                          "this host, and supplies the server for specs that omit one")
    src.add_argument("--var", action="append", default=[], metavar="K=V",
                     help="override a collection variable or spec parameter (repeatable)")

    auth = p.add_argument_group("credentials")
    auth.add_argument("-i", "--identities", metavar="FILE",
                      help="YAML identity profiles - see `gatecrash init`")
    auth.add_argument("-H", "--header", action="append", default=[], metavar="'K: V'",
                      help="header sent with every request (repeatable)")
    auth.add_argument("--token", metavar="TOKEN",
                      help="shorthand for -H 'Authorization: Bearer <TOKEN>'")

    beh = p.add_argument_group("behaviour")
    beh.add_argument("-p", "--profile", default="safe",
                     choices=["passive", "safe", "aggressive"],
                     help="passive: analyse the collection's own traffic only. "
                          "safe: non-destructive active checks (default). "
                          "aggressive: adds enumeration and management-surface probing.")
    beh.add_argument("--only", action="append", default=[], metavar="CHECK",
                     help="run only these check ids (repeatable, prefix match)")
    beh.add_argument("--skip", action="append", default=[], metavar="CHECK",
                     help="skip these check ids (repeatable, prefix match)")
    beh.add_argument("--scope", action="append", default=[], metavar="HOST",
                     help="host the scan may touch; '*.example.com' allowed (repeatable). "
                          "Defaults to the hosts found in the inputs.")
    beh.add_argument("--allow-destructive", action="store_true",
                     help="permit PUT/PATCH/DELETE. Off by default.")
    beh.add_argument("--safe-methods-only", action="store_true",
                     help="restrict the scan to GET/HEAD/OPTIONS")
    beh.add_argument("--rate-limit-burst", type=int, default=25, metavar="N",
                     help="requests used by the rate-limit probe (0 disables it; default 25)")
    beh.add_argument("--jwt-wordlist", metavar="FILE",
                     help="extra candidate secrets for offline JWT key recovery")
    beh.add_argument("--oast-domain", metavar="DOMAIN",
                     help="out-of-band callback domain (Burp Collaborator, interactsh) used "
                          "to confirm blind SSRF. gatecrash sends the payload; you check the "
                          "collaborator for the interaction.")
    beh.add_argument("--max-payload-kb", type=int, default=64, metavar="N",
                     help="size of the oversized-parameter probe in the aggressive profile "
                          "(default 64)")
    beh.add_argument("-y", "--yes", action="store_true",
                     help="skip the scope confirmation prompt")
    beh.add_argument("-n", "--dry-run", action="store_true",
                     help="show the scope, the endpoints, which of them would receive "
                          "state-changing requests, and the checks that would run - "
                          "then exit without sending anything")
    beh.add_argument("--redact", action="store_true",
                     help="mask credential header values in the reports, so evidence can "
                          "be shared without leaking live tokens")

    net = p.add_argument_group("network")
    net.add_argument("--rps", type=float, default=8.0, metavar="N",
                     help="max requests per second (default 8)")
    net.add_argument("-w", "--workers", type=int, default=6,
                     help="concurrent workers (default 6)")
    net.add_argument("--timeout", type=float, default=15.0, help="seconds (default 15)")
    net.add_argument("--max-requests", type=int, default=20000,
                     help="hard request budget for the run (default 20000)")
    net.add_argument("--proxy", metavar="URL",
                     help="route everything through a proxy, e.g. http://127.0.0.1:8080 "
                          "to record the scan in Burp")
    net.add_argument("-k", "--insecure", action="store_true",
                     help="do not verify TLS certificates")
    net.add_argument("--user-agent", default=f"gatecrash/{VERSION} (authorised security testing)")

    out = p.add_argument_group("output")
    out.add_argument("-o", "--out", default="./gatecrash-report", metavar="DIR",
                     help="report directory (default ./gatecrash-report)")
    out.add_argument("-f", "--format", default="html,json,md",
                     help="comma-separated: html,json,md (default all three)")
    out.add_argument("--fail-on", default=None,
                     choices=SEVERITY_ORDER,
                     help="exit non-zero if a finding of this severity or worse is found")
    out.add_argument("-v", "--verbose", action="count", default=0)
    out.add_argument("-q", "--quiet", action="store_true")


# --------------------------------------------------------------------------

def _setup_logging(verbose: int, quiet: bool) -> None:
    level = logging.WARNING
    if quiet:
        level = logging.ERROR
    elif verbose >= 2:
        level = logging.DEBUG
    elif verbose == 1:
        level = logging.INFO
    logging.basicConfig(level=level, format="%(levelname).1s %(message)s", stream=sys.stderr)


def _parse_vars(pairs: List[str]) -> Dict[str, str]:
    out = {}
    for pair in pairs:
        if "=" not in pair:
            raise SystemExit(f"--var expects KEY=VALUE, got {pair!r}")
        key, _, value = pair.partition("=")
        out[key.strip()] = value
    return out


def _gather_endpoints(args) -> List[Endpoint]:
    overrides = _parse_vars(args.var)
    endpoints: List[Endpoint] = []
    for path in args.collection:
        endpoints.extend(loaders.load_any(path, args.target, args.env, overrides))
    for url in args.url:
        full = url if "://" in url else (args.target or "https://") .rstrip("/") + "/" + url.lstrip("/")
        endpoints.append(Endpoint(method=args.method, url=full, source="--url"))
    return loaders.dedupe(endpoints)


def _derive_scope(args, endpoints: List[Endpoint], file_scope: List[str]) -> List[str]:
    scope = list(dict.fromkeys([s.strip() for s in args.scope + file_scope if s.strip()]))
    if scope:
        return scope
    hosts = []
    if args.target:
        host = urlsplit(args.target if "://" in args.target
                        else "https://" + args.target).netloc.split("@")[-1].split(":")[0]
        if host:
            hosts.append(host)
    for ep in endpoints:
        host = ep.host.split("@")[-1].split(":")[0]
        if host and host not in hosts:
            hosts.append(host)
    return hosts


def _write_endpoints(endpoints: List[Endpoint], args) -> List[Endpoint]:
    """Endpoints this run would send with a state-changing method."""
    if args.safe_methods_only:
        return []
    blocked = set() if args.allow_destructive else DESTRUCTIVE_METHODS
    return [e for e in endpoints
            if e.method not in ("GET", "HEAD", "OPTIONS") and e.method not in blocked]


def _confirm_scope(scope: List[str], endpoints: List[Endpoint], args) -> None:
    writes = _write_endpoints(endpoints, args)
    counts: Dict[str, int] = {}
    for endpoint in endpoints:
        counts[endpoint.method] = counts.get(endpoint.method, 0) + 1
    method_summary = ", ".join(f"{n}x {m}" for m, n in
                               sorted(counts.items(), key=lambda kv: -kv[1]))

    print(f"  Scope     : {', '.join(scope)}", file=sys.stderr)
    print(f"  Endpoints : {len(endpoints)}  ({method_summary})", file=sys.stderr)
    print(f"  Profile   : {args.profile}"
          f"{'  (PUT/PATCH/DELETE ENABLED)' if args.allow_destructive else ''}",
          file=sys.stderr)

    if writes:
        print(f"\n  \033[33mThis run will send state-changing requests to "
              f"{len(writes)} endpoint(s).\033[0m" if sys.stderr.isatty() else
              f"\n  This run will send state-changing requests to {len(writes)} endpoint(s).",
              file=sys.stderr)
        for endpoint in writes[:10]:
            print(f"    {endpoint.method:<7} {endpoint.path}", file=sys.stderr)
        if len(writes) > 10:
            print(f"    … and {len(writes) - 10} more", file=sys.stderr)
        print("  Each is replayed several times by the active checks, so expect "
              "duplicate records.\n  Use --safe-methods-only to test GET/HEAD/OPTIONS "
              "alone, or --profile passive\n  to send nothing beyond the collection's "
              "own requests.", file=sys.stderr)

    if args.dry_run:
        enabled = check_registry.select(args.profile, only=args.only, skip=args.skip)
        print(f"\n  Checks that would run ({len(enabled)}):", file=sys.stderr)
        for cls in enabled:
            print(f"    {cls.id:<28} {cls.severity:<9}"
                  f"{'passive' if cls.passive else 'active'}", file=sys.stderr)
        print("\n  --dry-run: nothing was sent.", file=sys.stderr)
        raise SystemExit(0)

    if args.yes or not sys.stdin.isatty():
        return
    print("\n  Only scan systems you have written authorisation to test.", file=sys.stderr)
    answer = input("  Proceed? [y/N] ").strip().lower()
    if answer not in ("y", "yes"):
        raise SystemExit("aborted")


def cmd_checks() -> int:
    print(f"{'CHECK ID':<28} {'SEVERITY':<9} {'PROFILES':<26} NAME")
    print("-" * 100)
    for check_id, cls in sorted(check_registry.REGISTRY.items()):
        profiles = ",".join(cls.profiles)
        tag = " (passive)" if cls.passive else ""
        print(f"{check_id:<28} {cls.severity:<9} {profiles:<26} {cls.name}{tag}")
    return 0


def cmd_scan(args) -> int:
    _setup_logging(args.verbose, args.quiet)
    if not args.quiet:
        print(BANNER % VERSION, file=sys.stderr)

    if not (args.collection or args.url):
        raise SystemExit("nothing to scan: pass -c <collection> and/or --url <url> "
                         "(see --help)")

    endpoints = _gather_endpoints(args)
    if not endpoints:
        raise SystemExit("no usable endpoints were parsed from the supplied inputs")

    identities, file_scope = load_identities(args.identities, args.header, args.token)
    identities = adopt_collection_credentials(identities, endpoints)
    scope = _derive_scope(args, endpoints, file_scope)
    if not scope:
        raise SystemExit("could not determine a scope - pass --scope or --target")
    _confirm_scope(scope, endpoints, args)

    wordlist: List[str] = []
    if args.jwt_wordlist:
        with open(args.jwt_wordlist, "r", encoding="utf-8", errors="replace") as fh:
            wordlist = [line.rstrip("\n") for line in fh if line.strip()]

    engine_config = EngineConfig(
        scope_hosts=scope, timeout=args.timeout, rps=args.rps,
        verify_tls=not args.insecure, proxy=args.proxy, user_agent=args.user_agent,
        allow_destructive=args.allow_destructive, max_requests=args.max_requests,
    )

    total = len(endpoints)
    state = {"n": 0}

    def progress(phase, endpoint, _payload):
        if args.quiet or phase != "baseline":
            return
        state["n"] += 1
        sys.stderr.write(f"\r  baselining {state['n']}/{total} endpoints ")
        sys.stderr.flush()
        if state["n"] == total:
            sys.stderr.write("\n")

    result = run_scan(
        endpoints, identities, engine_config,
        profile=args.profile, only=args.only, skip=args.skip, workers=args.workers,
        config={
            "rate_limit_burst": args.rate_limit_burst if args.profile != "passive" else 0,
            "jwt_wordlist": wordlist,
            "safe_methods_only": args.safe_methods_only,
            "oast_domain": args.oast_domain,
            "max_payload_kb": args.max_payload_kb,
        },
        progress=progress,
    )

    set_redaction(args.redact)
    target = args.target or (endpoints[0].scheme + "://" + endpoints[0].host)
    formats = tuple(f.strip() for f in args.format.split(",") if f.strip())
    written = report.write_all(args.out, result.findings, result.stats, target,
                               result.errors, formats)

    _print_summary(result, written, args)

    if args.fail_on:
        threshold = SEVERITY_ORDER.index(args.fail_on)
        if any(SEVERITY_ORDER.index(f.severity) <= threshold for f in result.findings):
            return 2
    return 0


def _print_summary(result, written: List[str], args) -> None:
    if args.quiet:
        for path in written:
            print(path)
        return
    counts = result.stats.get("severity_counts", {})
    colours = {"critical": "\033[91m", "high": "\033[93m", "medium": "\033[33m",
               "low": "\033[92m", "info": "\033[90m"}
    use_colour = sys.stdout.isatty()
    print("\n  Findings")
    for sev in SEVERITY_ORDER:
        n = counts.get(sev, 0)
        if not n:
            continue
        prefix = colours[sev] if use_colour else ""
        suffix = "\033[0m" if use_colour else ""
        print(f"    {prefix}{sev:<9}{suffix} {n}")
    if not result.findings:
        print("    none at this profile")

    top = [f for f in result.findings if f.severity in ("critical", "high")][:8]
    if top:
        print("\n  Highest severity")
        for f in top:
            print(f"    [{f.severity}] {f.endpoint} - {f.title}")

    print(f"\n  {result.stats['requests_sent']} requests across "
          f"{result.stats['endpoints_tested']} endpoints, "
          f"{result.stats['checks_run']} checks")
    if result.errors:
        print(f"  {len(result.errors)} request(s)/check(s) skipped or errored "
              f"(see the report)")
    print("\n  Reports")
    for path in written:
        print(f"    {os.path.abspath(path)}")
    print()


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "checks":
        return cmd_checks()
    if args.command == "init":
        print(IDENTITY_TEMPLATE)
        return 0
    return cmd_scan(args)


if __name__ == "__main__":
    sys.exit(main())
