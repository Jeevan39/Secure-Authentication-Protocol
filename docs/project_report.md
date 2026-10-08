# ACADEMIC PROJECT REPORT

## Design and Analysis of a Secure Authentication Protocol (SAP-v1.0)
*A Simplified SCRAM-Style Challenge-Response Authentication Protocol with Mutual Verification, At-Rest Verifier Sealing, Server-Side RBAC, and Synchronizer CSRF Mitigation*

---

### Abstract

Traditional web authentication architectures transmit plaintext credentials or static password hashes over Transport Layer Security (TLS) channels (`POST /login`). While TLS guarantees confidentiality in transit, it leaves credentials vulnerable to server-side memory scraping, logging exfiltration, malicious runtime dependencies, and Pass-the-Hash attacks upon database breach. 

This report presents the design, mathematical formulation, implementation, and empirical security analysis of the **Secure Authentication Protocol (SAP-v1.0)**. SAP-v1.0 implements a simplified challenge-response authentication scheme inspired by the design principles of RFC 5802 (SCRAM). Under this protocol, the plaintext password never leaves the client's local runtime. Authentication is achieved through a multi-step challenge-response handshake where the client demonstrates mathematical knowledge of the password using ephemeral 128-bit mutual nonces, PBKDF2-HMAC-SHA256 derivation, and HMAC-SHA256 proofs masked with bitwise XOR operations. Additionally, the server returns a verifiable `ServerProof`, enabling client-side validation of server authenticity (mutual verification).

To guarantee defense-in-depth, stored verifiers are sealed at rest using memory-hard **Argon2id** ($m=65536, t=3, p=4$) as an integrity seal to detect database tampering. The application enforces server-side Role-Based Access Control (RBAC) with strict 401/403 segregation, double-submit synchronizer CSRF tokens, a strictly hardened Content Security Policy (CSP without `unsafe-inline`), progressive account lockout with non-enumerating generic failure responses, and constant-time execution to prevent timing side-channels. Experimental verification across an automated 59-case test suite and a 7-scenario attack simulation suite demonstrates complete mitigation of Replay, Pass-the-Verifier, Nonce Tampering, Privilege Escalation, and CSRF attack vectors.

---

### Table of Contents

1. [Chapter 1: Introduction & Problem Statement](#chapter-1-introduction--problem-statement)
2. [Chapter 2: Literature Survey & Related Authentication Protocols](#chapter-2-literature-survey--related-authentication-protocols)
3. [Chapter 3: Cryptographic Architecture & Mathematical Derivations](#chapter-3-cryptographic-architecture--mathematical-derivations)
4. [Chapter 4: Authorization, CSRF & Defense-in-Depth Mechanisms](#chapter-4-authorization-csrf--defense-in-depth-mechanisms)
5. [Chapter 5: Threat Modeling & Security Analysis (STRIDE)](#chapter-5-threat-modeling--security-analysis-stride)
6. [Chapter 6: Implementation Details & Experimental Verification](#chapter-6-implementation-details--experimental-verification)
7. [Chapter 7: Limitations, Residual Risks & Engineering Trade-Offs](#chapter-7-limitations-residual-risks--engineering-trade-offs)
8. [Chapter 8: Conclusion & Future Scope](#chapter-8-conclusion--future-scope)
9. [References](#references)

---

### Chapter 1: Introduction & Problem Statement

#### 1.1 Background
Authentication forms the foundational perimeter of computer and network security. In classical client-server applications, authentication is typically performed using shared-secret schemes where the client delivers an identifier and a password to the server. The server verifies this secret against a database of stored cryptographic hashes generated via algorithms such as bcrypt, PBKDF2, or Argon2.

#### 1.2 Problem Statement
Despite widespread adoption of TLS 1.3, the traditional "password-over-HTTPS" paradigm suffers from three critical architectural flaws:

1. **Transient Server-Side Memory Exposure:** When a client sends a plaintext password to the server, the credential must be buffered in plaintext within the web application server's heap memory before hashing. Memory-scraping exploits, core dumps, memory-unsafe third-party dependencies, or compromised TLS termination proxies can intercept plaintext passwords without modifying the database.
2. **Pass-the-Hash / Pass-the-Verifier:** If an attacker gains read access to the database (via SQL injection, insider threat, or unencrypted backup leakage), storing static password hashes allows the attacker to conduct massive offline dictionary and rainbow-table attacks. In poorly designed protocols, possessing the hash directly enables session hijacking.
3. **Eavesdropping in Complex Networks:** In enterprise architectures featuring SSL inspection, reverse proxy clusters, or load balancers, plaintext credentials traverse internal networks in unencrypted or decrypted states between reverse proxies and upstream application servers.

#### 1.3 Project Objectives
The objective of this project is to architect, implement, evaluate, and formally document **SAP-v1.0**:
- **Challenge-Response Handshake:** Ensure that plaintext passwords are never transmitted over the network and never received or held in server memory.
- **Mutual Verification with ServerProof:** Enable the server to cryptographically prove possession of `ServerKey` back to the client.
- **At-Rest Verifier Sealing:** Implement Argon2id cryptographic sealing on stored verifiers to actively detect database tampering.
- **Replay & Tamper Immunity:** Employ mutual 128-bit CSPRNG nonces and atomic challenge consumption.
- **Server-Side Authorization:** Implement Role-Based Access Control (RBAC) ensuring unauthorized access attempts fail with strict HTTP 401/403 status codes.
- **Cross-Site Request Forgery Defense:** Enforce synchronizer token validation on authenticated state-changing endpoints.
- **Anti-Enumeration Protection:** Eliminate username and lockout enumeration via deterministic synthetic salts and constant-time execution.

---

### Chapter 2: Literature Survey & Related Authentication Protocols

| Protocol | Standard / RFC | Plaintext Transmitted? | Mutual Authentication? | At-Rest Verifier Security | Replay Resistance |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **HTTP Basic** | RFC 7617 | **Yes** (Base64) | No | None (Plaintext) | None |
| **HTTP Digest** | RFC 7616 | No (MD5/SHA) | No | Weak (Reversible MD5) | Nonce-based |
| **Kerberos v5** | RFC 4120 | No | **Yes** | Symmetric Key / KDC | Timestamp + Authenticator |
| **SRP-6a** | RFC 5054 | No | **Yes** | $g^x \pmod N$ | Ephemeral Public Keys |
| **SCRAM** | RFC 5802 | No | **Yes** | $\text{SHA256}(\text{ClientKey})$ | Mutual Nonces |
| **SAP-v1.0 (Ours)**| Educational | **No** (SCRAM-Style) | **Yes** (ServerProof) | **Argon2id Sealed Verifier** | **Mutual Nonces + Atomic DB** |

#### 2.1 Digest Authentication (RFC 7616)
HTTP Digest attempted to remove plaintext passwords from network transit by sending MD5/SHA-256 hashes of the password combined with a realm and nonce. However, the server was required to store either the plaintext password or the raw hash `MD5(username:realm:password)`, making the server verifier equivalent to the plaintext password (Pass-the-Hash vulnerability).

#### 2.2 Secure Remote Password (SRP-6a / RFC 5054)
SRP is an augmented Password-Authenticated Key Exchange (PAKE) based on the Discrete Logarithm Problem in modular arithmetic. While mathematically robust, SRP is computationally expensive, requires modular exponentiation of 2048-bit numbers, and is complex to implement reliably in browser JavaScript runtimes.

#### 2.3 Salted Challenge Response (SCRAM / RFC 5802 Principles)
SCRAM addresses the weaknesses of Digest and the complexity of SRP by employing standard HMAC and hash primitives with provable security properties. SAP-v1.0 builds upon the SCRAM conceptual framework by integrating browser-native W3C Web Cryptography APIs on the client, atomic SQLite challenge lifecycle management on the server, mutual server proof verification, and memory-hard Argon2id verifier integrity sealing.

---

### Chapter 3: Cryptographic Architecture & Mathematical Derivations

#### 3.1 Domain Separation & Key Derivation Chain

Let $P$ denote the plaintext password, $S$ denote a 16-byte cryptographically secure random salt, and $N = 100,000$ denote the PBKDF2 iteration count.

1. **Master Key Derivation:**
   $$\text{MasterKey} = \text{PBKDF2-HMAC-SHA256}(P, S, N, \text{length}=32)$$

2. **Domain Separation:**
   $$\text{ClientKey} = \text{HMAC-SHA256}(\text{MasterKey}, \text{"client-key-v1"})$$

3. **Stored Verifier Derivation:**
   $$\text{StoredKey} = \text{SHA-256}(\text{ClientKey})$$

4. **Server Proof Secret:**
   $$\text{ServerProof} = \text{HMAC-SHA256}(\text{SERVER\_PROOF\_SECRET}, \text{AuthMessage})$$

The database stores $\{S, N, \text{StoredKey}, \text{verifier\_seal}\}$, but **never** stores $\text{MasterKey}$, $\text{ClientKey}$, or $P$. The server proof secret (`SERVER_PROOF_SECRET`) is managed as an application-level secret loaded from the environment/configuration and is decoupled from the user authentication database table. `ServerProof` provides server-origin authentication as long as the server authentication secret remains protected from database compromise.

#### 3.2 Handshake Protocol with Server Verification

```text
CLIENT                                                          SERVER
  │                                                               │
  │ 1. Client Hello: { username, client_nonce }                  │
  ├──────────────────────────────────────────────────────────────►│
  │                                                               │
  │    Server generates server_nonce (16 bytes CSPRNG)            │
  │    Creates ephemeral challenge record (60s TTL, status=issued)│
  │                                                               │
  │ 2. Server Challenge: { server_nonce, salt, iterations, id }   │
  │◄──────────────────────────────────────────────────────────────┤
  │                                                               │
  │ Client derives MasterKey, ClientKey, StoredKey                │
  │ Computes AuthMessage = "SAP-v1.0" || context || username ||   │
  │                        client_nonce || server_nonce           │
  │ Computes ClientSignature = HMAC(StoredKey, AuthMessage)       │
  │ Computes ClientProof = ClientKey ⊕ ClientSignature            │
  │                                                               │
  │ 3. Client Proof Submission: { client_nonce, server_nonce, id, proof }
  ├──────────────────────────────────────────────────────────────►│
  │                                                               │
  │    Atomic DB Transaction:                                     │
  │    Check challenge: issued? unexpired? matching nonces?       │
  │    Consume challenge: status = 'consumed'                     │
  │    Verify Argon2id Seal: Verify(StoredKey, verifier_seal)     │
  │    Reconstruct AuthMessage                                    │
  │    Compute ClientSignature = HMAC(StoredKey, AuthMessage)     │
  │    Recover ClientKey = ClientProof ⊕ ClientSignature          │
  │    Verify: SHA256(RecoveredClientKey) == StoredKey            │
  │    Compute ServerSignature = HMAC(SERVER_PROOF_SECRET, AuthMessage)
  │                                                               │
  │ 4. Verification Response: { server_proof, status=success }    │
  │◄──────────────────────────────────────────────────────────────┤
  │                                                               │
  │ Client validates ServerProof format and signature             │
  │ Session established upon mutual confirmation                  │
```

#### 3.3 Mathematical Proof of Correctness
The server recovers $\text{ClientKey}$ through the involution property of the bitwise XOR operator ($\oplus$):
$$\text{RecoveredClientKey} = \text{ClientProof} \oplus \text{ClientSignature}$$
Substituting $\text{ClientProof} = \text{ClientKey} \oplus \text{ClientSignature}$:
$$\text{RecoveredClientKey} = (\text{ClientKey} \oplus \text{ClientSignature}) \oplus \text{ClientSignature}$$
Since $X \oplus Y \oplus Y = X$:
$$\text{RecoveredClientKey} = \text{ClientKey}$$
The server then evaluates:
$$\text{SHA-256}(\text{RecoveredClientKey}) \stackrel{?}{=} \text{StoredKey}$$
If the hashes match identically under constant-time comparison (`hmac.compare_digest`), the client has proven knowledge of $\text{ClientKey}$ (and therefore $P$) without disclosing it.

Subsequently, the server returns:
$$\text{ServerProof} = \text{HMAC-SHA256}(\text{SERVER\_PROOF\_SECRET}, \text{AuthMessage})$$
The client receives $\text{ServerProof}$, confirming server origin as long as the application server secret is protected from unauthorized disclosure. ServerProof provides server-origin authentication as long as the server authentication secret remains protected from database compromise; it does not claim to protect against host-level compromises.

#### 3.4 Role and Limits of Argon2id Verifier Sealing
In this protocol, $\text{StoredKey}$ must be available in symmetric form for the server to calculate $\text{ClientSignature}$. It cannot be replaced by an unkeyed slow hash without breaking the protocol.

Argon2id is applied as an **at-rest integrity seal**:
$$\text{verifier\_seal} = \text{Argon2id}(\text{StoredKey})$$
The server validates this seal during challenge verification. If an adversary modifies or injects verifiers directly into the database, seal verification fails and the authentication handshake terminates immediately. **Importantly, Argon2id does not eliminate offline dictionary attacks against weak passwords if the database is exfiltrated**; offline security against stolen verifiers is fundamentally bounded by the work factor of PBKDF2 ($100,000$ iterations) and the user's password entropy.

---

### Chapter 4: Authorization, CSRF & Defense-in-Depth Mechanisms

#### 4.1 Server-Side Role-Based Access Control (RBAC)
The application enforces a strict two-tier authorization model:
- `role = 'user'`: Standard authenticated user with access to `/dashboard` and `/logs`.
- `role = 'admin'`: Elevated administrator with access to `/admin` and `/api/admin/unlock/<user_id>`.

Authorization is enforced server-side using the `@require_role('admin')` Python decorator:
- Unauthenticated requests $\to$ **HTTP 401 Unauthorized**.
- Authenticated non-admin requests $\to$ **HTTP 403 Forbidden** (with `ACCESS_DENIED_UNAUTHORIZED_ROLE` audit event logged).
- Public registration endpoints hardcode `role = 'user'`, neutralizing self-registration privilege escalation.

#### 4.2 Cross-Site Request Forgery (CSRF) Mitigation
SAP-v1.0 implements the **Double-Submit Synchronizer Token Pattern**:
- Every response sets a 256-bit cryptographically secure pseudorandom token in a `csrf_token` cookie (`SameSite=Lax`, `Path=/`).
- Authenticated state-changing HTTP requests (`POST`, `PUT`, `DELETE`, `PATCH`) must supply this token in the `X-CSRF-Token` header.
- The server performs constant-time validation (`hmac.compare_digest(submitted, cookie)`).
- **Scope Justification:** Administrative actions (`/api/admin/unlock/*`) strictly require CSRF validation. Cryptographic handshake endpoints are exempt because they require ephemeral nonce-bound HMAC proof generation that cannot be forged cross-origin.

#### 4.3 HTTP Security Headers & Content Security Policy (CSP)
Every HTTP response contains strict modern security headers:
- `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self';`
- `X-Frame-Options: DENY` (Anti-Clickjacking)
- `X-Content-Type-Options: nosniff` (Anti-MIME Sniffing)
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Cache-Control: no-store, no-cache, must-revalidate, max-age=0` (Anti-Caching)

Notably, `'unsafe-inline'` and `'unsafe-eval'` are completely eliminated from the CSP. All script and style logic is segregated into standalone static assets.

---

### Chapter 5: Threat Modeling & Security Analysis (STRIDE)

| Threat Vector | Status | Protection / Security Control |
| :--- | :---: | :--- |
| **Replay attack** | **MITIGATED** | Mutual CSPRNG nonces (`client_nonce` + `server_nonce`), 60s challenge TTL, and atomic single-use status transition in SQLite transactions. |
| **Password eavesdropping** | **MITIGATED** | Client-side WebCrypto PBKDF2/HMAC key derivation; plaintext password is never transmitted across the network. Production deployment requires TLS for transport encryption. |
| **Brute-force password guessing** | **PARTIALLY MITIGATED** | Failed attempt counter, progressive delays, and temporary 5-minute lockout after 5 consecutive failures. Distributed attacks require IP/WAF rate limiting. |
| **Username / lockout enumeration** | **MITIGATED** | Uniform HTTP 401 error responses across all failure states, deterministic synthetic salt derivation, and constant-time dummy verifier processing paths. |
| **Session hijacking** | **PARTIALLY MITIGATED** | Unpredictable 256-bit CSPRNG tokens, SHA-256 token hashing at rest, sliding 15m idle / 24h absolute expiration, and HttpOnly/SameSite cookies. External TLS required to protect cookies in transit. |
| **Session fixation** | **MITIGATED** | Pre-existing session state is invalidated and regenerated with a fresh cryptographically random session token upon authentication boundary traversal. |
| **Cross-Site Request Forgery (CSRF)** | **MITIGATED** | Cryptographically strong synchronizer CSRF tokens stored in session and enforced via `X-CSRF-Token` headers on privileged state-changing endpoints with constant-time comparison. |
| **Cross-Site Scripting (XSS)** | **MITIGATED** | Strict Content Security Policy (`script-src 'self'`; no `unsafe-inline`), Jinja2 template auto-escaping, and strict regex input sanitization. |
| **SQL injection** | **MITIGATED** | Strict character whitelist regex validation (`^[a-zA-Z0-9_.-]{3,32}$`) and universal parameterized SQLite queries (`?` placeholders). |
| **Privilege escalation** | **MITIGATED** | Server-side Role-Based Access Control (`@require_role`) enforcing dual-tier authorization (`user`, `admin`) with segregated HTTP 401/403 status codes. Registration role forcing. |
| **Database compromise / exfiltration** | **PARTIALLY MITIGATED** | Pass-the-verifier prevented via one-way `StoredKey = SHA256(ClientKey)`. 100k PBKDF2 iterations and Argon2id seal impose high work factor. Weak passwords remain vulnerable to offline guessing. |
| **ServerProof secret compromise** | **OUT OF SCOPE** | `SERVER_PROOF_SECRET` is decoupled from the database into application configuration. If the application host environment is compromised, the secret is compromised. |
| **TLS / MITM transport attacks** | **OUT OF SCOPE** | Application protocol operates above transport layer. Production deployments strictly require external TLS/HTTPS termination. |
| **Denial of Service (DoS)** | **PARTIALLY MITIGATED** | Indexed database lookups, 60s challenge TTL cleanup, and client-side offload of PBKDF2 prevent server CPU exhaustion. Volumetric DDoS requires network-level edge filtering. |

---

### Chapter 6: Implementation Details & Experimental Verification

#### 6.1 Technology Stack
- **Backend Framework:** Python 3.10+ / Flask Application Factory
- **Database Engine:** SQLite 3 with Write-Ahead Logging (WAL) and immediate transactional locking
- **Cryptography Libraries:** Python `hashlib`, `hmac`, `secrets`, `argon2-cffi`
- **Frontend Layer:** Semantic HTML5, CSS3 Custom Properties, JavaScript W3C Web Cryptography API (`crypto.subtle`)
- **Testing Framework:** `pytest` 9.1+

#### 6.2 Experimental Test Suite Results
An automated test suite consisting of **59 test cases** was executed across 8 test suites:

```text
============================= test session starts =============================
platform win32 -- Python 3.14.6, pytest-9.1.1, pluggy-1.6.0
rootdir: C:\Users\USER\Desktop\Secure Authentication Protocol
collected 59 items

tests/test_admin.py (4 tests)                      .................... PASSED [  7%]
tests/test_authentication.py (7 tests)             .................... PASSED [ 19%]
tests/test_database.py (5 tests)                   .................... PASSED [ 27%]
tests/test_frontend.py (6 tests)                   .................... PASSED [ 37%]
tests/test_registration.py (6 tests)               .................... PASSED [ 47%]
tests/test_security_hardening.py (15 tests)        .................... PASSED [ 73%]
tests/test_sessions.py (8 tests)                   .................... PASSED [ 86%]
tests/test_verifier.py (8 tests)                   .................... PASSED [100%]

============================= 59 passed in 13.06s =============================
```

#### 6.3 Live Threat Simulation Suite
The terminal attack simulation suite ([`demos/attack_simulation.py`](file:///c:/Users/USER/Desktop/Secure%20Authentication%20Protocol/demos/attack_simulation.py)) verified all 7 attack scenarios in real time:
1. Replay Attack Mitigation $\to$ **PASS (HTTP 401)**
2. Pass-the-Verifier Mitigation $\to$ **PASS (HTTP 401)**
3. Nonce Tampering in Transit $\to$ **PASS (HTTP 401)**
4. Brute-Force Lockout & Anti-Enumeration $\to$ **PASS (HTTP 401 / DB Locked)**
5. Privilege Escalation & RBAC $\to$ **PASS (HTTP 403)**
6. CSRF Attack Mitigation $\to$ **PASS (HTTP 403 / HTTP 200)**
7. Verifier Seal Tampering $\to$ **PASS (HTTP 401)**

---

### Chapter 7: Limitations, Residual Risks & Engineering Trade-Offs

1. **Client-Side JavaScript Trust Boundary:** Challenge-response execution requires the browser to execute untampered JavaScript (`authentication.js`). If an adversary compromises the host server, they could alter the script to exfiltrate passwords before derivation. In production, this requires strict HTTPS, Subresource Integrity (SRI), and certificate pinning.
2. **Offline Dictionary Attacks on Leaked Verifiers:** While `StoredKey` cannot be used to authenticate directly, an attacker who obtains the raw database can attempt offline dictionary attacks against PBKDF2. Our 100,000 iteration threshold and Argon2id verifier seal impose substantial computational costs, but users must still adhere to strong password policies.
3. **Single-Node Session Storage:** The current implementation stores hashed session tokens in a local SQLite table. In distributed high-availability architectures, session storage should be migrated to a distributed, replicated Redis cluster.

---

### Chapter 8: Conclusion & Future Scope

SAP-v1.0 demonstrates that web applications do not need to rely on the insecure transmission of plaintext passwords over HTTP. By combining the challenge-response mathematical principles of RFC 5802 SCRAM with mutual server proof verification, Argon2id verifier sealing, server-side RBAC, synchronizer CSRF tokens, and constant-time execution, the system achieves a technically defensible, highly secure authentication perimeter suitable for high-security environments.

**Future Scope:**
1. Integration of W3C WebAuthn / FIDO2 hardware security keys for multi-factor authentication (MFA).
2. Implementation of client-side WebAssembly (Wasm) Argon2id hashing once browser hardware acceleration matures.
3. Distributed session cluster support using Redis with encrypted token storage.

---

### References
1. Newman, C., et al. (2010). *Salted Challenge Response Authentication Mechanism (SCRAM) SASL and GSS-API Mechanisms*. RFC 5802, Internet Engineering Task Force.
2. Wu, T. (2007). *The Secure Remote Password (SRP) Protocol Version 6a*. RFC 5054, Internet Engineering Task Force.
3. Biryukov, A., Dinu, D., & Khovratovich, D. (2016). *Argon2: the memory-hard function for password hashing and other applications*. Password Hashing Competition.
4. Franks, J., et al. (1999). *HTTP Authentication: Basic and Digest Access Authentication*. RFC 2617, Internet Engineering Task Force.
5. OWASP Foundation. (2025). *Cross-Site Request Forgery (CSRF) Prevention Cheat Sheet*. OWASP Cheat Sheet Series.
6. NIST Special Publication 800-63B. (2020). *Digital Identity Guidelines: Authentication and Lifecycle Management*. National Institute of Standards and Technology.
