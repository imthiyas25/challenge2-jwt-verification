# Challenge 2 — Remediation Verification Report
**JWT Algorithm Confusion | FIND-0087**

This repository covers all five parts of Challenge 2: written threat analysis, test case design, AI-assisted workflow documentation, implementation notes, and systems design.

---

## Folder Structure

```
challenge2-jwt-verification/
├── verify_jwt.py                    ← Part D — working verification script
├── jwt_server.py                    ← local test server (fixed RS256 version)
├── config.json                      ← input config (target, strategies, key path)
├── server_public.pem                ← RSA public key for token manipulation
├── server_private.pem               ← RSA private key (used by jwt_server.py)
├── Challenge2_Submission.docx       ← full written report (Parts A–E)
└── evidence/
    ├── jwt_report_*.json            ← auto-generated tamper-evident reports
    └── screenshots/                 ← terminal output screenshots
```

---

## Setup

```bash
# Install dependencies
pip3 install flask pyjwt cryptography requests --break-system-packages

# Generate RSA key pair (if not already present)
openssl genrsa -out server_private.pem 2048
openssl rsa -in server_private.pem -pubout -out server_public.pem
```

---

## How to Run

### Run Against Local Test Server (shows PASS results)

**Terminal 1 — Start the fixed JWT server:**
```bash
python3 jwt_server.py
```

**Terminal 2 — Run the verifier:**
```bash
python3 verify_jwt.py config.json
```

### CLI Flags

```bash
python3 verify_jwt.py config.json            # normal run with full output
python3 verify_jwt.py config.json --quiet    # verdict only
python3 verify_jwt.py config.json --verbose  # full token and response detail
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | REMEDIATION_VERIFIED |
| `1` | REMEDIATION_FAILED |
| `2` | INCONCLUSIVE |

---

## Sample Output

```
===== REMEDIATION VERIFICATION REPORT =====
Finding  : jwt_algorithm_confusion
Target   : https://httpbin.org/get
Timestamp: 2026-03-13T09:00:00Z

[TC-01] Strategy : alg_none
        Status   : 401 | Time: 0.31s | Sensitive: NO
        Result   : PASS

[TC-02] Strategy : hs256_with_pubkey
        Status   : 200 | Time: 0.28s | Sensitive: NO
        Result   : FAIL -- Server accepted manipulated token

===== VERDICT: REMEDIATION FAILED =====
Failed Tests: 1 / 4
Evidence saved : evidence/jwt_report_20260313T090000Z.json
Report hash    : sha256:9f2c1a3b...
```

---

## Part A — Threat Modelling the Fix [25 pts]

### Q1. What is the algorithm confusion attack and why did it work originally?

A JSON Web Token (JWT) is a three-part Base64URL-encoded structure: header, payload, and signature. The header declares the signing algorithm (e.g., alg: RS256), and the server must use only that algorithm — verified against a trusted key — to authenticate the token. RS256 is asymmetric: the server signs with its private key and verifies with its public key. The public key is, by design, meant to be shared.

The algorithm confusion attack exploits a critical flawed assumption: the vulnerable server trusted the client-supplied alg header field to decide which algorithm to use, rather than enforcing a server-side allowlist. An attacker who obtains the server's public key can craft a new token with alg: HS256 and sign it using the RS256 public key as the HMAC secret. The vulnerable server reads alg: HS256, treats the public key as the shared HMAC secret, and verifies the signature — which succeeds, since the attacker used that exact key to sign. A forged token is accepted as legitimate.

**Root cause:** The original code called a generic `jwt.verify(token, publicKey)` without specifying `algorithms: ['RS256']` — a one-line omission that allows the algorithm to be downgraded to a symmetric scheme the attacker fully controls.

---

### Q2. Five distinct ways the fix could still be incomplete or bypassed:

| # | Bypass Vector | Mechanism |
|---|--------------|-----------|
| 1 | alg: none accepted | Some JWT libraries accept 'none' as a valid algorithm, bypassing signature verification entirely if the server does not explicitly reject it. |
| 2 | kid header injection | If the server uses the kid (Key ID) header to look up keys from a filesystem path, an attacker can inject kid: '../../dev/null' and sign with an empty HMAC secret. |
| 3 | Library-level bug | Older versions of PyJWT (<2.4), jsonwebtoken (<9.0), and golang-jwt have bugs where algorithm enforcement fails for mixed-case alg values (e.g. 'Hs256' vs 'HS256'). |
| 4 | Fallback code path | Legacy endpoints, debug routes, or middleware layers that pre-date the RS256 patch may still accept HS256 tokens, bypassing the fix on non-primary paths. |
| 5 | Response caching | If a load balancer or CDN cached a 200 OK from before the fix was deployed, attackers can receive a cached valid response even though the backend now correctly rejects the token. |

---

### Q3. Three measurable conditions required to declare the fix successful:

1. **Condition 1 — Algorithm enforcement verified:** The server returns HTTP 401 for every token presenting alg: HS256, alg: none, alg: '' (blank), or any algorithm other than RS256, confirmed across all endpoints.

2. **Condition 2 — Original exploit rejected:** A token crafted with alg: HS256, signed using the actual RS256 public key as the HMAC secret (the original CVE payload), returns HTTP 401 with no sensitive data in the response body.

3. **Condition 3 — Legitimate RS256 token accepted:** A properly signed RS256 token continues to return HTTP 200, confirming the fix did not break normal authentication. Fixing security without breaking functionality is the verification threshold.

---

### Q4. Does 24-hour JWT secret rotation strengthen the fix?

No — secret rotation is irrelevant to this specific vulnerability. Secret rotation is meaningful for symmetric schemes (HS256/HS512) where a leaked shared secret can be rotated. However, RS256 uses an asymmetric key pair. The server's public key does not need to be kept secret — it is, by design, public. Rotating it does not prevent the attack because the attacker only needs the current public key (obtainable from the JWKS endpoint at the time of attack) to forge a new HS256 token. The root problem is the server accepting algorithm downgrades. Secret rotation provides no additional protection until strict algorithm enforcement is in place.

---

## Part B — Test Case Design [25 pts]

Minimum viable test suite for FIND-0087. Target: `GET /api/v1/admin/users`. Expected rejection code: 401.

> Note: TC-02 = client-claim-specific test. TC-07 = library-level test.

| Test ID | Category | Token Modification | Expected (Vulnerable) | Expected (Fixed) | Pass Condition |
|---------|----------|-------------------|----------------------|-----------------|----------------|
| TC-01 | alg:none attack | Set alg='none', strip signature | 200 OK — admin list returned | 401 Unauthorized | Status 401, no sensitive data in body |
| TC-02 | Original exploit (client-claim) | alg='HS256', sign with RS256 public key as HMAC secret | 200 OK — admin list returned | 401 Unauthorized | Status 401; RS256-only enforcement confirmed |
| TC-03 | alg header removal | Remove alg field from header entirely | 200 OK or 500 | 401 Unauthorized | Status 401, no 500 server error |
| TC-04 | kid header injection | Inject kid='../../dev/null', sign with empty HMAC | 200 OK (null-key bypass) | 401 Unauthorized | Status 401, kid field rejected |
| TC-05 | Expired token | Set exp=0, iat=0, keep original RS256 signature | 200 OK (exp not checked) | 401 Unauthorized | Status 401; expiry validation confirmed |
| TC-06 | Tampered payload (role escalation) | Change role='admin' in payload; invalid signature | 200 OK (signature not verified) | 401 Unauthorized | Status 401; signature integrity enforced |
| TC-07 | Blank alg (library-level) | Set alg='' (empty string); tests PyJWT/jsonwebtoken case-folding bug | 200 OK (library bug bypasses check) | 401 Unauthorized | Status 401; blank alg rejected at library level |
| TC-08 | RS256 mismatched key | Correct alg=RS256 but signature made with wrong private key | 200 OK (signature not verified) | 401 Unauthorized | Status 401; cryptographic verification confirmed |

---

## Part C — AI-Assisted Workflow [20 pts]

### Prompt Used

> "Generate a Python function that takes a JWT, a target API endpoint, and a list of token manipulation strategies, applies each strategy, sends the modified token in the Authorization header, and returns a structured result indicating whether the server accepted or rejected each token."

### Raw AI Output (verbatim)

```python
import jwt, requests, base64, json, hmac, hashlib

def test_jwt_strategies(token, endpoint, strategies):
    results = []
    for strategy in strategies:
        modified = apply_strategy(token, strategy)
        resp = requests.get(endpoint, headers={'Authorization': f'Bearer {modified}'})
        results.append({'strategy': strategy, 'status': resp.status_code,
                         'accepted': resp.status_code == 200})
    return results

def apply_strategy(token, strategy):
    parts = token.split('.')
    header = json.loads(base64.b64decode(parts[0] + '=='))
    payload = json.loads(base64.b64decode(parts[1] + '=='))
    if strategy == 'alg_none':
        header['alg'] = 'none'
        return encode_token(header, payload, '')
    elif strategy == 'hs256_with_pubkey':
        header['alg'] = 'HS256'
        key = open('public.pem').read()
        return encode_token(header, payload, key)
```

### Critique — What Was Wrong or Unsafe

1. No timeout on `requests.get()`. A hung request blocks the function indefinitely. Fix: add `timeout=10`.
2. Hardcoded `'public.pem'` path. The key path must be a parameter, not a hardcoded assumption.
3. `base64.b64decode` with `'=='` padding is wrong for JWT. JWT uses URL-safe Base64 with variable-length padding omitted. Adding `'=='` blindly causes decode errors. Correct: compute padding as `4 - len(s)%4`.
4. HMAC called with `secret.encode()` — fails for binary PEM keys. The RS256 public key is binary PEM data, not a UTF-8 string. Must be read as bytes and passed directly.
5. Missing error handling. If strategy name is unknown, `apply_strategy()` returns None silently, causing a crash in `encode_token()`.
6. `alg:none` tokens get a valid HMAC signature. A correct `alg:none` token must have an empty signature field (just a trailing dot), not a computed signature.
7. `tamper_role_to_admin` uses empty-string HMAC. Should leave signature as `'invalidsignature'` to test whether the server verifies signatures, not sign with an empty secret.
8. No response body inspection for sensitive data. A 200 status is not the only failure signal — the server might return 200 with leaked data.

### Corrected Version

The corrected implementation is in `verify_jwt.py` (Part D). Key improvements: URL-safe base64 with correct padding; public key read as raw bytes; per-request timeout; alg:none produces empty signature; tamper strategies produce invalid signatures; sensitive data pattern scanning; all unknown strategies raise ValueError; full structured output per test case.

---

## Part D — Implementation Sprint [20 pts]

The working script is submitted as `verify_jwt.py`. It accepts a JSON config file and supports all four required strategies plus four additional ones (kid injection, alg header removal, blank alg, RS256 wrong key). Anomaly detection covers status code, response time (>3s), and sensitive data patterns.

**Bonus implemented:** evidence JSON and SHA-256 hash are saved to an `evidence/` directory automatically on every run.

### Anomaly Detection

| Signal | Condition |
|--------|-----------|
| BEHAVIORAL | Status code != expected rejection code |
| TEMPORAL | Response time > 3 seconds |
| CONTENT | Sensitive data pattern found in response body |

---

## Part E — Systems Design Under Pressure [10 pts]

*Word count: ~185 words (within 150–200 limit)*

The pipeline should adopt a strategy pattern with a central registry mapping finding types to verifier classes. The core engine loads a finding record, reads its type field, looks up the registered strategy, and delegates all test generation, execution, and anomaly detection to that strategy class. Adding a new finding type requires only: (1) creating a new strategy class that inherits from the shared BaseVerifier interface, and (2) registering it with one line. The core engine never changes.

All strategies must share a standardised contract covering five dimensions: input schema (finding record with required fields), test case structure (test_id, category, payload, expected_status), anomaly signals (behavioral: status code; temporal: p95 excess; content: body hash or canary), result format (PASS / FAIL / ERROR), and evidence schema (JSON report with SHA-256 hash). Finding-specific signals — OOB callbacks for SSRF, gadget chain triggers for deserialization — are overrides inside the strategy, invisible to the core. This separation ensures the engine scales to any vulnerability class without modification.

---

## Submission Checklist

- [x] Part A — Threat modelling written answers (Q1, Q2, Q3, Q4)
- [x] Part B — 8 test cases in table format
- [x] Part C — AI prompt used + raw output + critique + corrected code
- [x] Part D — Working `verify_jwt.py` with sample output + bonus evidence hash
- [x] Part E — Systems design answer (~185 words, within 150–200 limit)
- [x] Bonus — Evidence JSON + SHA-256 hash saved to `evidence/` automatically
- [x] Screenshots — Terminal output screenshots in `evidence/screenshots/`
