# Academic Defense & Viva Presentation Guide (SAP-v1.0)
**Project Title:** Design and Analysis of a Secure Authentication Protocol (SAP-v1.0)  
**Evaluation Target:** 5 / 5 Grade Defense Presentation  

---

## 1. The 60-Second Elevator Pitch

> *"Most modern web applications transmit plaintext passwords over HTTPS (`POST /login`). Even with TLS encryption in transit, this means the server memory buffers the plaintext password, exposing it to heap memory scraping, process inspection, and server-side log leakage. Furthermore, traditional password hashing schemes are vulnerable to Pass-the-Hash if the database is compromised.*
>
> *Our project, **SAP-v1.0**, solves this by implementing a **Simplified SCRAM-Style Challenge-Response Authentication Protocol** inspired by RFC 5802 design principles. Under our protocol, the plaintext password never touches the network and never reaches the server. The client proves mathematical possession of the password using ephemeral 128-bit nonces and HMAC proofs, while the server proves its authenticity back to the client using a verifiable ServerProof (`HMAC-SHA256(SERVER_PROOF_SECRET, AuthMessage)`) derived from an isolated application-level secret.*
>
> *To achieve a defense-in-depth architecture, we integrated **Argon2id Verifier Sealing** to verify stored verifier integrity at rest, implemented strict **server-side Role-Based Access Control (RBAC)**, double-submit **synchronizer CSRF protection**, and hardened the application with strict **Content Security Policy** headers (no `unsafe-inline`), and **non-enumerating progressive 5-attempt brute-force lockout**."*

---

## 2. Live Demonstration Script for Examiners

When asked to demonstrate the project, execute these commands in sequence:

### Step 1: Live Terminal Attack Simulation Suite (2 Minutes)
Run the automated attack simulator to demonstrate all 7 threat mitigations in real-time:
```powershell
python demos/attack_simulation.py
```
**What to highlight to the examiner:**
1. **Replay Attack:** Shows an eavesdropper replaying an intercepted proof. Blocked because the server nonce was atomically consumed in the SQLite database.
2. **Pass-the-Verifier:** Shows an attacker exfiltrating `StoredKey` from SQLite. Blocked because `SHA-256` is a one-way preimage-resistant function and the attacker cannot calculate `ClientKey`.
3. **Nonce Tampering:** Shows a Man-in-the-Middle altering nonces. Blocked because the HMAC `AuthMessage` signature is invalidated.
4. **Brute-Force Lockout & Anti-Enumeration:** Shows 5 consecutive failed attempts triggering an account lockout in SQLite, while externally returning generic HTTP 401 responses to eliminate username/lockout enumeration.
5. **Privilege Escalation & RBAC:** Shows a normal user attempting to access `/admin` or invoke `/api/admin/unlock`. Blocked with HTTP 403 Forbidden.
6. **CSRF Protection:** Shows a cross-origin forged request attempting an account unlock. Blocked with HTTP 403.
7. **Argon2id Verifier Seal:** Shows direct SQLite tampering with verifiers. Blocked because the Argon2id integrity seal fails.

---

### Step 2: Automated Test Suite (1 Minute)
Execute the complete test suite:
```powershell
pytest -v
```
**Result:** **59 passing tests** across 8 test suites (`test_admin`, `test_authentication`, `test_database`, `test_frontend`, `test_registration`, `test_security_hardening`, `test_sessions`, `test_verifier`).

---

### Step 3: Interactive Browser Demonstration (3 Minutes)
Launch the Flask application:
```powershell
python app.py
```
Open **[http://127.0.0.1:5000](http://127.0.0.1:5000)**:

1. **User vs. Admin Demonstration:**
   - Log in with `jeevan39` (Standard User).
   - Show that the user can access their Dashboard and Security Logs, but **cannot** see the Admin Console.
   - Manually type `http://127.0.0.1:5000/admin` in the browser URL bar: The server displays **HTTP 403 Forbidden**.
2. **Admin Console Demonstration:**
   - Click **Logout**.
   - Log in with `admin` / `Admin@123456`.
   - Show the **Admin Console** button in the navbar and dashboard.
   - Open `/admin` to show live telemetry, active hashed sessions, and the STRIDE threat matrix with explicitly labeled `MITIGATED`, `PARTIALLY MITIGATED`, and `OUT OF SCOPE` boundaries.
   - Click the red **`🚪 Logout (Admin)`** button to prove clean session revocation.

---

## 3. Top 10 Viva Defense Questions & Winning Technical Answers

### Q1: What is the core difference between your protocol and standard bcrypt/Argon2 password hashing?
> **Answer:** In standard password hashing, the client sends the plaintext password over HTTP to the server, and the server runs `bcrypt.checkpw(password, hash)`. In SAP-v1.0, the plaintext password is never sent to the server. The client performs PBKDF2 locally to derive a `ClientKey`, and computes an HMAC proof over fresh 128-bit server nonces. The server verifies this mathematical proof without ever seeing or storing the password.

### Q2: What is the mathematical equation behind the client's authentication proof?
> **Answer:**
> 1. $\text{AuthMessage} = \text{"SAP-v1.0"} \parallel \text{context} \parallel \text{username} \parallel \text{client\_nonce} \parallel \text{server\_nonce}$
> 2. $\text{ClientSignature} = \text{HMAC-SHA256}(\text{StoredKey}, \text{AuthMessage})$
> 3. $\text{ClientProof} = \text{ClientKey} \oplus \text{ClientSignature}$
>
> The server computes $\text{RecoveredClientKey} = \text{ClientProof} \oplus \text{ClientSignature}$, and verifies that $\text{SHA-256}(\text{RecoveredClientKey}) == \text{StoredKey}$ using constant-time comparison.

### Q3: How does your protocol achieve server verification with ServerProof?
> **Answer:** Upon verifying the client proof, the server computes a server proof:
> $$\text{ServerProof} = \text{HMAC-SHA256}(\text{SERVER\_PROOF\_SECRET}, \text{AuthMessage})$$
> using an application-level secret (`SERVER_PROOF_SECRET`) decoupled from the user authentication database table, and delivers it to the client in the verification response. The client validates the server proof format and signature before persisting the session. ServerProof provides server-origin authentication as long as the server authentication secret remains protected from database compromise.

### Q4: Why is Argon2id used as an integrity seal rather than the primary verifier? Does it prevent offline dictionary attacks?
> **Answer:** Challenge verification requires the server to use the verifier as an HMAC secret key ($\text{StoredKey}$). Argon2id outputs formatted hash strings, not symmetric cryptographic keys. If we replaced $\text{StoredKey}$ with an Argon2id hash, the server would lack the symmetric key to compute the HMAC. Thus, Argon2id is applied as an at-rest integrity seal ($\text{verifier\_seal} = \text{Argon2id}(\text{StoredKey})$) to detect database tampering. **Critically, Argon2id does not eliminate offline dictionary attacks against an exfiltrated database if weak passwords are used**; offline resistance against exfiltrated verifiers relies on client-side PBKDF2 iterations and user password entropy.

### Q5: How does your system eliminate username and account enumeration?
> **Answer:** Both unknown accounts and temporarily locked accounts receive uniform handling:
> 1. At `/api/auth/challenge`, unknown usernames receive a deterministic synthetic salt via $\text{HMAC-SHA256}(\text{ServerPepper}, \text{username})[0:16]$, and locked accounts receive standard challenge parameters (HTTP 200).
> 2. At `/api/auth/verify`, all authentication failures (unknown username, wrong proof, locked account) return an identical generic HTTP 401 response: *"Authentication failed. Please verify your credentials and try again."*
> Internal audit logs distinguish `UNKNOWN_USER_AUTH_FAILED`, `INVALID_PROOF`, and `ACCOUNT_LOCKED`, but external observers cannot determine account existence or lockout state.

### Q6: How does your protocol prevent replay attacks?
> **Answer:** Replay attacks are mitigated by:
> 1. Ephemeral 128-bit mutual nonces (`client_nonce` and `server_nonce`) generated by CSPRNG (`secrets.token_hex(16)`).
> 2. Strict 60-second Time-To-Live (TTL).
> 3. Atomic single-use challenge consumption: The challenge record is marked `status = 'consumed'` in an immediate SQLite transaction before the proof is verified. Any second attempt with the same challenge ID or nonces is rejected.

### Q7: Why are raw session tokens not stored in your database?
> **Answer:** Storing raw session tokens in the database exposes all active sessions to hijacking if the database is dumped or read via SQL injection. In SAP-v1.0, the client receives a 256-bit random session token in an `HttpOnly` cookie, but the database only stores $\text{SHA-256}(\text{token})$. If the database is compromised, the attacker cannot reverse the hash to impersonate active sessions.

### Q8: What role does the Content Security Policy (CSP) play?
> **Answer:** Because the challenge-response authentication relies on browser JavaScript WebCrypto, preventing Cross-Site Scripting (XSS) is paramount. Our CSP (`default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; frame-ancestors 'none';`) completely disallows `'unsafe-inline'` and `'unsafe-eval'`. All event listeners and styles reside in external files, preventing script injection and frame hijacking.

### Q9: Why is PBKDF2 configured with 100,000 iterations?
> **Answer:** 100,000 iterations of PBKDF2-HMAC-SHA256 represents an academically calibrated balance for web applications. Benchmarks demonstrate that 100,000 iterations execute in ~35–45 ms in browser WebCrypto via native hardware acceleration, ensuring responsive user experience while imposing a substantial computational penalty on offline password cracking attempts.

### Q10: What are the residual risks and out-of-scope boundaries?
> **Answer:** In our formal STRIDE analysis:
> - **Partially Mitigated:** Offline dictionary attacks on database exfiltration (bounded by password entropy and 100k PBKDF2) and online brute-force (mitigated by 5-attempt progressive lockout).
> - **Out of Scope:** Client endpoint compromise / malware keyloggers (if the browser or OS is compromised, credentials can be read before derivation), TLS termination infrastructure compromise / rogue root CAs, and quantum cryptanalysis.
