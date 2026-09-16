#!/usr/bin/env python3
"""
openid_fed_probe — detect whether an OpenID Provider implements OpenID Federation 1.0.

Why three probes:
  OpenID Federation support is NOT signalled by WebFinger. WebFinger
  (/.well-known/webfinger) is OIDC's *issuer discovery* mechanism: it maps a
  user identifier to an issuer. Federation support is signalled by the
  *entity configuration* published at /.well-known/openid-federation (a signed
  `entity-statement+jwt`), and hinted at by federation fields in the OIDC
  discovery document. This tool chains all three so the verdict is grounded in
  the actually-authoritative endpoint while still reporting what WebFinger says.

I/O model:
  - INPUT   : a CSV of providers (alias,issuer[,notes]). This is the source of
              truth for the provider list — there is no hardcoded alias table.
  - LOG     : every HTTP request and response is appended to a JSONL audit log
              (URL + method + request headers sent, and status + headers + body
              received). One JSON object per request.
  - OUTPUT  : a results CSV, one row per provider, with the verdict and the
              key signals from each of the three probes.

Spec references:
  - OpenID Connect Discovery 1.0 §2 (WebFinger issuer discovery)
  - OpenID Connect Discovery 1.0 §4 (/.well-known/openid-configuration)
  - OpenID Federation 1.0 §9 (Entity Statements) and §6 (/.well-known/openid-federation)

Zero dependencies. Requires Python 3.7+ (standard library only).
"""

import argparse
import base64
import csv
import datetime
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

OIDC_ISSUER_REL = "http://openid.net/specs/connect/1.0/issuer"
ENTITY_STATEMENT_TYP = "entity-statement+jwt"
ENTITY_STATEMENT_CT = "application/entity-statement+jwt"
DEFAULT_TIMEOUT_S = 10.0
DEFAULT_INPUT = "providers.csv"
DEFAULT_OUTPUT = "results.csv"
DEFAULT_LOG = "probe-log.jsonl"
MAX_LOG_BODY = 200000  # cap logged response bodies to keep the log sane

# OIDC-discovery fields defined by OpenID Federation 1.0. Their presence in the
# discovery document is a strong secondary signal of federation support.
FEDERATION_DISCOVERY_FIELDS = [
    "client_registration_types_supported",
    "federation_registration_endpoint",
    "request_authentication_methods_supported",
    "request_authentication_signing_alg_values_supported",
]

# Audit log. Every HTTP request/response pair is recorded here and flushed to a
# JSONL file at the end of the run.
LOG = []


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def http_get(url, ctx):
    """Fetch a URL (GET), recording the full request/response into LOG. Returns a
    dict with ok/status/content_type/body, or an error field. Never raises for
    HTTP status."""
    request_headers = {"User-Agent": "openid-fed-probe/1.0", "Accept": "*/*"}
    entry = {
        "ts": _now(),
        "provider": ctx.get("provider"),
        "issuer": ctx.get("issuer"),
        "probe": ctx.get("probe"),
        "request": {"method": "GET", "url": url, "headers": request_headers},
        "response": None,
    }
    timeout = ctx.get("timeout", DEFAULT_TIMEOUT_S)
    req = urllib.request.Request(url, headers=request_headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
            entry["response"] = _resp_entry(resp.status, True,
                                            resp.headers.get("content-type", "") or "",
                                            dict(resp.headers.items()), resp.geturl(), body)
            LOG.append(entry)
            return {"ok": True, "status": resp.status,
                    "content_type": resp.headers.get("content-type", "") or "", "body": body}
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", "replace")
        except Exception:
            pass
        ct = e.headers.get("content-type", "") if e.headers else ""
        headers = dict(e.headers.items()) if e.headers else {}
        entry["response"] = _resp_entry(e.code, False, ct, headers, url, body)
        LOG.append(entry)
        return {"ok": False, "status": e.code, "content_type": ct, "body": body}
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        reason = getattr(e, "reason", e)
        is_timeout = isinstance(reason, TimeoutError) or "timed out" in str(reason).lower()
        error = "timeout" if is_timeout else str(reason)
        entry["response"] = {"status": 0, "ok": False, "error": error}
        LOG.append(entry)
        return {"ok": False, "status": 0, "error": error}


def _resp_entry(status, ok, content_type, headers, final_url, body):
    return {
        "status": status,
        "ok": ok,
        "content_type": content_type,
        "headers": headers,
        "final_url": final_url,
        "body_length": len(body),
        "body_truncated": len(body) > MAX_LOG_BODY,
        "body": body[:MAX_LOG_BODY] if len(body) > MAX_LOG_BODY else body,
        "error": None,
    }


def load_catalog(path):
    """Load the provider catalog from CSV. Requires `alias` and `issuer` columns;
    `notes` is optional. Rows without an issuer are skipped."""
    out = []
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        cols = [c.lower() for c in (reader.fieldnames or [])]
        if "alias" not in cols or "issuer" not in cols:
            raise ValueError("input CSV must have 'alias' and 'issuer' columns; got: %s"
                             % ", ".join(reader.fieldnames or []))
        # Build a case-insensitive column accessor.
        for raw in reader:
            row = {(k or "").lower(): (v or "") for k, v in raw.items()}
            issuer = row.get("issuer", "").strip()
            if not issuer:
                continue
            alias = row.get("alias", "").strip() or issuer
            out.append({"alias": alias, "issuer": issuer, "notes": row.get("notes", "").strip()})
    return out


def normalize_issuer(value):
    url = value
    if not url.lower().startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def well_known_append(issuer, suffix):
    """OIDC Discovery 1.0 §4 appends the well-known path AFTER the issuer's path
    component (e.g. Azure's /common/v2.0)."""
    return "{}/.well-known/{}".format(issuer.rstrip("/"), suffix)


def well_known_insert(issuer, suffix):
    """OpenID Federation 1.0 §9 / RFC 8414 INSERT the well-known path BETWEEN the
    host and the issuer's path component."""
    parts = urllib.parse.urlsplit(issuer)
    path = parts.path.rstrip("/")
    new_path = "/.well-known/{}{}".format(suffix, path)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, new_path, "", ""))


def b64url_decode(seg):
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad).decode("utf-8", "replace")


def decode_jwt(compact):
    """Decode a compact JWS without verifying the signature. Signature
    verification requires the trust chain (out of scope for a presence probe),
    so we only parse."""
    parts = compact.strip().split(".")
    if len(parts) != 3:
        return None
    try:
        return {"header": json.loads(b64url_decode(parts[0])),
                "payload": json.loads(b64url_decode(parts[1]))}
    except Exception:
        return None


def probe_webfinger(issuer, ctx):
    # WebFinger is served at the host root, independent of any issuer path.
    origin = urllib.parse.urlsplit(issuer)
    base = "{}://{}/.well-known/webfinger".format(origin.scheme, origin.netloc)
    query = urllib.parse.urlencode({"resource": ctx.get("resource") or issuer, "rel": OIDC_ISSUER_REL})
    endpoint = base + "?" + query
    res = http_get(endpoint, dict(ctx, probe="webfinger"))
    out = {"endpoint": endpoint, "status": res["status"], "implemented": False, "issuer": None}
    if res.get("error"):
        out["error"] = res["error"]
        return out
    if not res["ok"]:
        return out
    try:
        jrd = json.loads(res["body"])
        out["implemented"] = True
        for link in jrd.get("links", []):
            if link.get("rel") == OIDC_ISSUER_REL and link.get("href"):
                out["issuer"] = link["href"]
                break
    except Exception:
        pass
    return out


def probe_discovery(issuer, ctx):
    endpoint = well_known_append(issuer, "openid-configuration")
    res = http_get(endpoint, dict(ctx, probe="discovery"))
    out = {"endpoint": endpoint, "status": res["status"], "implemented": False, "federation_fields": []}
    if res.get("error"):
        out["error"] = res["error"]
        return out
    if not res["ok"]:
        return out
    try:
        meta = json.loads(res["body"])
        out["implemented"] = True
        out["issuer"] = meta.get("issuer")
        out["federation_fields"] = [f for f in FEDERATION_DISCOVERY_FIELDS if f in meta]
        types = meta.get("client_registration_types_supported")
        if isinstance(types, list):
            out["client_registration_types"] = types
    except Exception:
        out["error"] = "invalid JSON in discovery document"
    return out


def probe_federation(issuer, ctx):
    endpoint = well_known_insert(issuer, "openid-federation")
    res = http_get(endpoint, dict(ctx, probe="federation"))
    out = {"endpoint": endpoint, "status": res["status"], "implemented": False,
           "looks_like_entity": False, "checks": {}, "reasons": []}
    if res.get("error"):
        out["error"] = res["error"]
        return out
    if not res["ok"]:
        out["reasons"].append("HTTP {}".format(res["status"]))
        return out

    jwt = decode_jwt(res["body"])
    if not jwt:
        out["reasons"].append("response is not a compact JWT")
        return out

    header, payload = jwt["header"], jwt["payload"]
    c = out["checks"]
    c["content_type"] = ENTITY_STATEMENT_CT in (res.get("content_type") or "")
    c["typ_header"] = header.get("typ") == ENTITY_STATEMENT_TYP
    c["self_issued"] = bool(payload.get("iss") and payload.get("iss") == payload.get("sub"))
    jwks = payload.get("jwks")
    c["has_jwks"] = bool(jwks and (isinstance(jwks, list) or jwks.get("keys")))
    c["has_metadata"] = isinstance(payload.get("metadata"), dict)
    c["has_authority_hints"] = isinstance(payload.get("authority_hints"), list)

    out["entity"] = {
        "iss": payload.get("iss"),
        "sub": payload.get("sub"),
        "metadata_types": list(payload.get("metadata", {}).keys()) if c["has_metadata"] else [],
        "authority_hints": payload.get("authority_hints", []),
        "alg": header.get("alg"),
    }

    out["looks_like_entity"] = c["self_issued"] and c["has_jwks"] and c["has_metadata"]
    well_typed = c["typ_header"] or c["content_type"]
    out["implemented"] = out["looks_like_entity"] and well_typed
    if not c["self_issued"]:
        out["reasons"].append("iss/sub not present or not self-issued")
    if not c["has_jwks"]:
        out["reasons"].append("no jwks in payload")
    if not c["has_metadata"]:
        out["reasons"].append("no metadata in payload")
    if out["looks_like_entity"] and not well_typed:
        out["reasons"].append(
            "media type not {} (typ={}, content-type={})".format(
                ENTITY_STATEMENT_TYP, header.get("typ"), res.get("content_type") or "none"))
    return out


def classify(fed, disc):
    if fed["implemented"]:
        return {"verdict": "SUPPORTED", "confidence": "high",
                "reason": "serves a valid self-issued entity configuration at /.well-known/openid-federation"}
    if fed.get("looks_like_entity"):
        return {"verdict": "LIKELY", "confidence": "medium",
                "reason": "entity configuration present but with caveats: " + "; ".join(fed["reasons"])}
    if disc.get("federation_fields"):
        return {"verdict": "LIKELY", "confidence": "medium",
                "reason": "discovery advertises federation fields: " + ", ".join(disc["federation_fields"])}
    # No federation signal. Before calling it "not supported", separate a host we
    # simply could not reach (DNS/connection/timeout — no HTTP response at all on
    # the discovery or federation endpoint) from one that answered but has no
    # federation. status == 0 means the probe never got an HTTP response back.
    if disc.get("status", 0) == 0 and fed.get("status", 0) == 0 and not disc.get("implemented"):
        detail = fed.get("error") or disc.get("error") or "no response"
        return {"verdict": "UNREACHABLE", "confidence": "n/a",
                "reason": "could not reach discovery or federation endpoints (%s)" % detail}
    return {
        "verdict": "NOT SUPPORTED",
        "confidence": "high" if disc.get("implemented") else "low",
        "reason": ("no federation entity configuration and no federation fields in discovery"
                   if disc.get("implemented")
                   else "reachable but no valid OIDC discovery and no federation entity configuration"),
    }


def probe_provider(value, issuer, opts):
    ctx = {"provider": value, "issuer": issuer,
           "resource": opts.get("resource"), "timeout": opts.get("timeout", DEFAULT_TIMEOUT_S)}
    webfinger = probe_webfinger(issuer, ctx)
    discovery = probe_discovery(issuer, ctx)
    federation = probe_federation(issuer, ctx)
    classification = classify(federation, discovery)
    return {"input": value, "issuer": issuer, "webfinger": webfinger,
            "discovery": discovery, "federation": federation, "classification": classification}


RESULT_HEADERS = [
    "input", "issuer", "verdict", "confidence", "reason",
    "webfinger_status", "webfinger_implemented", "webfinger_issuer",
    "discovery_status", "discovery_implemented", "discovery_federation_fields",
    "federation_status", "federation_implemented", "federation_iss",
    "federation_metadata_types", "federation_authority_hints",
]


def to_result_row(r):
    f = r["federation"]
    e = f.get("entity") or {}
    return {
        "input": r["input"], "issuer": r["issuer"],
        "verdict": r["classification"]["verdict"], "confidence": r["classification"]["confidence"],
        "reason": r["classification"]["reason"],
        "webfinger_status": r["webfinger"]["status"], "webfinger_implemented": r["webfinger"]["implemented"],
        "webfinger_issuer": r["webfinger"].get("issuer") or "",
        "discovery_status": r["discovery"]["status"], "discovery_implemented": r["discovery"]["implemented"],
        "discovery_federation_fields": "|".join(r["discovery"].get("federation_fields", [])),
        "federation_status": f["status"], "federation_implemented": f["implemented"],
        "federation_iss": e.get("iss") or "",
        "federation_metadata_types": "|".join(e.get("metadata_types", [])),
        "federation_authority_hints": "|".join(e.get("authority_hints", [])),
    }


def print_human(results):
    print("")
    print("{:<22}{:<16}{:<8}{}".format("PROVIDER", "FEDERATION", "CONF", "DETAIL"))
    print("-" * 100)
    for r in results:
        c = r["classification"]
        print("{:<22}{:<16}{:<8}{}".format(r["input"], c["verdict"], c["confidence"], c["reason"]))
    print("")


HELP_EPILOG = """
By default the tool reads every provider from the input CSV and probes them all.
Pass one or more providers to probe a subset instead; each may be an alias from
the input CSV, a domain (accounts.google.com), or a full issuer URL.

Outputs:
  - stdout  : a human-readable verdict table
  - --log   : one JSON object per HTTP request (url, method, request headers,
              response status, response headers, and response body)
  - --output: one CSV row per provider with the verdict and per-probe signals

Verdicts:
  SUPPORTED       valid self-issued entity configuration at /.well-known/openid-federation
  LIKELY          federation endpoint responded imperfectly, or discovery advertises federation fields
  NOT SUPPORTED   reachable, but neither federation signal present
  UNREACHABLE     no HTTP response from the discovery or federation endpoint (DNS/connection/timeout)
"""


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="openid_fed_probe.py",
        description="Detect OpenID Federation 1.0 support in an OpenID Provider.",
        epilog=HELP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("providers", nargs="*", help="subset of aliases/domains/issuer URLs to probe")
    parser.add_argument("--input", default=DEFAULT_INPUT, help="provider CSV alias,issuer[,notes] (default %(default)s)")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="results CSV to write (default %(default)s)")
    parser.add_argument("--log", default=DEFAULT_LOG, help="request/response audit log, JSONL (default %(default)s)")
    parser.add_argument("--json", action="store_true", help="also print machine-readable JSON to stdout")
    parser.add_argument("--resource", default=None,
                        help="WebFinger resource (e.g. acct:user@domain); defaults to the issuer")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_S,
                        help="per-request timeout in seconds (default %(default)s)")
    args = parser.parse_args(argv)

    catalog = []
    if os.path.exists(args.input):
        catalog = load_catalog(args.input)
    elif not args.providers:
        sys.stderr.write("error: input CSV '%s' not found and no providers given.\n" % args.input)
        sys.stderr.write("Provide --input <csv> or pass provider URLs/aliases as arguments.\n")
        return 1
    alias_map = {r["alias"].lower(): r["issuer"] for r in catalog}

    if args.providers:
        targets = [{"input": p, "issuer": normalize_issuer(alias_map.get(p.lower(), p))}
                   for p in args.providers]
    else:
        targets = [{"input": r["alias"], "issuer": normalize_issuer(r["issuer"])} for r in catalog]

    if not targets:
        sys.stderr.write("error: no providers to probe.\n")
        return 1

    opts = {"resource": args.resource, "timeout": args.timeout}
    results = [probe_provider(t["input"], t["issuer"], opts) for t in targets]

    # Flush the audit log (JSONL) and the results CSV.
    with open(args.log, "w", encoding="utf-8") as fh:
        for entry in LOG:
            fh.write(json.dumps(entry) + "\n")
    with open(args.output, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=RESULT_HEADERS)
        writer.writeheader()
        for r in results:
            writer.writerow(to_result_row(r))

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print_human(results)

    sys.stderr.write("log:     %d requests -> %s\n" % (len(LOG), args.log))
    sys.stderr.write("results: %d providers -> %s\n" % (len(results), args.output))
    return 0


if __name__ == "__main__":
    sys.exit(main())
