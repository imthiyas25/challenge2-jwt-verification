#!/usr/bin/env python3
import sys, json, time, hmac, hashlib, base64, argparse, re, os
from datetime import datetime, timezone
import requests
from cryptography.hazmat.primitives import serialization

SENSITIVE_PATTERNS = [
    re.compile(r'"role"\s*:\s*"admin"', re.IGNORECASE),
    re.compile(r'"users"\s*:', re.IGNORECASE),
    re.compile(r'"email"\s*:', re.IGNORECASE),
    re.compile(r'Authorization', re.IGNORECASE),
]

def b64url_decode(s):
    s = s.replace("-", "+").replace("_", "/")
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.b64decode(s)

def b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def decode_token_parts(token):
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(f"Invalid JWT: expected 3 parts, got {len(parts)}")
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    return header, payload, parts[2]

def build_token(header, payload, signature_bytes):
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    s = b64url_encode(signature_bytes)
    return f"{h}.{p}.{s}"

def build_unsigned_token(header, payload):
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}."

def strategy_alg_none(original_token, pubkey_bytes):
    header, payload, _ = decode_token_parts(original_token)
    header["alg"] = "none"
    header.pop("typ", None)
    return build_unsigned_token(header, payload)

def strategy_hs256_with_pubkey(original_token, pubkey_bytes):
    header, payload, _ = decode_token_parts(original_token)
    header["alg"] = "HS256"
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(pubkey_bytes, signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{b64url_encode(sig)}"

def strategy_tamper_role_to_admin(original_token, pubkey_bytes):
    header, payload, _ = decode_token_parts(original_token)
    payload["role"] = "admin"
    return build_token(header, payload, b"invalidsignature")

def strategy_expired_token(original_token, pubkey_bytes):
    header, payload, _ = decode_token_parts(original_token)
    payload["exp"] = 1000000
    return build_token(header, payload, b"invalidsignature")

def strategy_kid_injection(original_token, pubkey_bytes):
    header, payload, _ = decode_token_parts(original_token)
    header["kid"] = "../../dev/null"
    return build_token(header, payload, b"invalidsignature")

def strategy_blank_alg(original_token, pubkey_bytes):
    header, payload, _ = decode_token_parts(original_token)
    header["alg"] = ""
    return build_token(header, payload, b"invalidsignature")

STRATEGY_MAP = {
    "alg_none": strategy_alg_none,
    "hs256_with_pubkey": strategy_hs256_with_pubkey,
    "tamper_role_to_admin": strategy_tamper_role_to_admin,
    "expired_token": strategy_expired_token,
    "kid_injection": strategy_kid_injection,
    "blank_alg": strategy_blank_alg,
}

def detect_sensitive_data(body):
    return any(p.search(body) for p in SENSITIVE_PATTERNS)

def supports_color():
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

def green(s):  return f"\033[32m{s}\033[0m" if supports_color() else s
def red(s):    return f"\033[31m{s}\033[0m" if supports_color() else s
def yellow(s): return f"\033[33m{s}\033[0m" if supports_color() else s
def bold(s):   return f"\033[1m{s}\033[0m"  if supports_color() else s

def main():
    parser = argparse.ArgumentParser(description="JWT Algorithm Confusion Verifier")
    parser.add_argument("config", nargs="?", default="config.json")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    with open(args.config) as f:
        cfg = json.load(f)

    target = cfg["target"]
    finding = cfg["finding"]
    original_token = cfg["original_token"]
    pubkey_path = cfg["public_key_path"]
    strategies = cfg["test_strategies"]
    expected_rejection = cfg.get("expected_rejection_code", 401)

    with open(pubkey_path, "rb") as f:
        pubkey_bytes = f.read()

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if not args.quiet:
        print(bold("===== REMEDIATION VERIFICATION REPORT ====="))
        print(f"Finding  : {finding}")
        print(f"Target   : {target}")
        print(f"Timestamp: {timestamp}")
        print()

    results = []
    passed = failed = 0

    for idx, strategy_name in enumerate(strategies, start=1):
        tc_id = f"TC-{idx:02d}"
        if strategy_name not in STRATEGY_MAP:
            print(yellow(f"[{tc_id}] Unknown strategy '{strategy_name}' — skipping"))
            continue

        modified_token = STRATEGY_MAP[strategy_name](original_token, pubkey_bytes)

        start = time.monotonic()
        try:
            resp = requests.get(
                target,
                headers={"Authorization": f"Bearer {modified_token}"},
                timeout=10,
            )
            elapsed = time.monotonic() - start
            status_code = resp.status_code
            body = resp.text
        except Exception as exc:
            elapsed = time.monotonic() - start
            status_code = None
            body = ""

        anomalies = []
        if status_code != expected_rejection:
            anomalies.append(f"expected {expected_rejection}, got {status_code}")
        if elapsed > 3.0:
            anomalies.append(f"response time {elapsed:.2f}s exceeded 3s")
        if detect_sensitive_data(body):
            anomalies.append("sensitive data detected in response body")

        result = "PASS" if not anomalies else "FAIL"
        if result == "PASS":
            passed += 1
        else:
            failed += 1

        res = {
            "test_id": tc_id,
            "strategy": strategy_name,
            "status_code": status_code,
            "response_time_s": round(elapsed, 3),
            "sensitive_data": detect_sensitive_data(body),
            "anomalies": anomalies,
            "result": result,
        }
        results.append(res)

        if not args.quiet:
            colour = green if result == "PASS" else red
            print(f"[{tc_id}] Strategy : {strategy_name}")
            if args.verbose:
                print(f"        Token    : {modified_token[:80]}...")
            print(f"        Status   : {status_code} | Time: {elapsed:.2f}s | Sensitive: {'YES' if detect_sensitive_data(body) else 'NO'}")
            print(f"        Result   : {colour(result)}")
            if anomalies:
                for a in anomalies:
                    print(f"        → {a}")
            print()

    total = len(results)
    verdict = "REMEDIATION_FAILED" if failed > 0 else "REMEDIATION_VERIFIED"
    exit_code = 1 if failed > 0 else 0

    report = {
        "finding": finding,
        "target": target,
        "timestamp": timestamp,
        "verdict": verdict,
        "summary": {"total": total, "passed": passed, "failed": failed},
        "test_results": results,
    }
    report_json = json.dumps(report, indent=2)
    report_hash = "sha256:" + hashlib.sha256(report_json.encode()).hexdigest()
    report["report_hash"] = report_hash

    os.makedirs("evidence", exist_ok=True)
    ts_clean = timestamp.replace(":", "").replace("-", "")
    evidence_file = f"evidence/jwt_report_{ts_clean}.json"
    with open(evidence_file, "w") as f:
        json.dump(report, f, indent=2)

    if not args.quiet:
        print(bold("=" * 44))
        colour = green if verdict == "REMEDIATION_VERIFIED" else red
        print(bold(f"===== VERDICT: {colour(verdict)} ====="))
        print(f"Failed Tests   : {failed} / {total}")
        print(f"Evidence saved : {evidence_file}")
        print(f"Report hash    : {report_hash}")
    else:
        print(green(verdict) if verdict == "REMEDIATION_VERIFIED" else red(verdict))

    sys.exit(exit_code)

if __name__ == "__main__":
    main()
