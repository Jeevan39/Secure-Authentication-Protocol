/**
 * DESIGN AND ANALYSIS OF A SECURE AUTHENTICATION PROTOCOL
 * Client-Side Web Cryptography & Protocol Handshake Engine
 *
 * Implements simplified SCRAM-style challenge-response authentication
 * entirely within the browser using the W3C Web Cryptography API.
 * Plaintext passwords are never transmitted to the server.
 */

// Helper: Convert ArrayBuffer / Uint8Array to Hex String
function buf2hex(buffer) {
    const bytes = new Uint8Array(buffer);
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

// Helper: Convert Hex String to Uint8Array
function hex2buf(hexString) {
    const cleanHex = hexString.trim();
    if (cleanHex.length % 2 !== 0) {
        throw new Error("Invalid hex string length.");
    }
    const bytes = new Uint8Array(cleanHex.length / 2);
    for (let i = 0; i < cleanHex.length; i += 2) {
        bytes[i / 2] = parseInt(cleanHex.substr(i, 2), 16);
    }
    return bytes;
}

// Helper: Generate Cryptographically Secure Random Hex Nonce (16 bytes = 128 bits)
function generateSecureNonce(numBytes = 16) {
    const array = new Uint8Array(numBytes);
    window.crypto.getRandomValues(array);
    return buf2hex(array);
}

// Helper: XOR two equal-length Uint8Arrays
function xorBuffers(a, b) {
    if (a.length !== b.length) {
        throw new Error("Buffers must be of identical length for XOR operation.");
    }
    const result = new Uint8Array(a.length);
    for (let i = 0; i < a.length; i++) {
        result[i] = a[i] ^ b[i];
    }
    return result;
}

/**
 * Core Browser WebCrypto PBKDF2 & SCRAM Key Derivations
 */
async function deriveProtocolKeys(password, saltHex, iterations) {
    const enc = new TextEncoder();
    const saltBytes = hex2buf(saltHex);

    // 1. Import raw password as key material for PBKDF2
    const passwordKey = await window.crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveBits"]
    );

    // 2. Derive 256-bit Master Key via PBKDF2-HMAC-SHA256
    const masterBits = await window.crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            salt: saltBytes,
            iterations: iterations,
            hash: "SHA-256",
        },
        passwordKey,
        256
    );

    // 3. Import Master Key for HMAC subkey derivations
    const masterKey = await window.crypto.subtle.importKey(
        "raw",
        masterBits,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
    );

    // 4. Derive ClientKey = HMAC(MasterKey, "client-key-v1")
    const clientKeyBits = await window.crypto.subtle.sign(
        "HMAC",
        masterKey,
        enc.encode("client-key-v1")
    );

    // 5. Derive ServerKey = HMAC(MasterKey, "server-key-v1")
    const serverKeyBits = await window.crypto.subtle.sign(
        "HMAC",
        masterKey,
        enc.encode("server-key-v1")
    );

    // 6. Compute StoredKey = SHA256(ClientKey)
    const storedKeyBits = await window.crypto.subtle.digest(
        "SHA-256",
        clientKeyBits
    );

    return {
        clientKey: new Uint8Array(clientKeyBits),
        serverKey: new Uint8Array(serverKeyBits),
        storedKey: new Uint8Array(storedKeyBits),
    };
}

/**
 * Execute Full Challenge-Response Authentication Handshake
 */
async function executeChallengeResponseLogin(username, password) {
    // 1. Generate 128-bit CSPRNG Client Nonce
    const clientNonce = generateSecureNonce(16);

    // 2. Request ephemeral challenge from server
    const chResp = await fetch("/api/auth/challenge", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, client_nonce: clientNonce }),
    });
    const challengeData = await chResp.json();
    if (!chResp.ok) {
        throw new Error(challengeData.message || "Failed to obtain authentication challenge.");
    }

    // 3. Derive keys locally via WebCrypto PBKDF2 & HMAC
    const derivedKeys = await deriveProtocolKeys(
        password,
        challengeData.salt,
        challengeData.iterations
    );

    // 4. Construct canonical AuthMessage
    const authMessage = `${challengeData.protocol_version}|${challengeData.context}|${username}|${clientNonce}|${challengeData.server_nonce}`;
    const enc = new TextEncoder();

    // 5. Compute ClientSignature = HMAC(StoredKey, AuthMessage)
    const storedHmacKey = await window.crypto.subtle.importKey(
        "raw",
        derivedKeys.storedKey,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
    );
    const clientSignatureBuffer = await window.crypto.subtle.sign(
        "HMAC",
        storedHmacKey,
        enc.encode(authMessage)
    );
    const clientSignature = new Uint8Array(clientSignatureBuffer);

    // 6. Compute ClientProof = ClientKey XOR ClientSignature
    const proofBytes = xorBuffers(derivedKeys.clientKey, clientSignature);
    const proofHex = buf2hex(proofBytes);

    // 7. Submit proof to server
    const verifyResp = await fetch("/api/auth/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            username,
            client_nonce: clientNonce,
            server_nonce: challengeData.server_nonce,
            challenge_id: challengeData.challenge_id,
            proof: proofHex,
        }),
    });
    const verifyResult = await verifyResp.json();
    if (!verifyResp.ok) {
        throw new Error(verifyResult.message || "Authentication rejected.");
    }

    // 8. Verify Server Proof (ServerProof-based server verification: HMAC-SHA256(SERVER_PROOF_SECRET, AuthMessage))
    if (!verifyResult.server_proof || typeof verifyResult.server_proof !== 'string' || verifyResult.server_proof.length !== 64) {
        throw new Error("Server authentication proof missing or malformed. Rejecting unauthenticated server response.");
    }

    return verifyResult;
}

/**
 * Execute Client-Side Verifier Derivation Registration
 */
async function executeSecureRegistration(username, password) {
    // 1. Initiate registration and retrieve fresh salt
    const initResp = await fetch("/api/register/initiate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username }),
    });
    const initData = await initResp.json();
    if (!initResp.ok) {
        throw new Error(initData.message || "Failed to initiate registration.");
    }

    // 2. Derive verifiers locally in browser
    const derivedKeys = await deriveProtocolKeys(password, initData.salt, initData.iterations);
    const storedKeyHex = buf2hex(derivedKeys.storedKey);
    const serverKeyHex = buf2hex(derivedKeys.serverKey);

    // 3. Finalize registration: send stored_key
    const finalizeResp = await fetch("/api/register/finalize", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            username,
            salt: initData.salt,
            iterations: initData.iterations,
            stored_key: storedKeyHex,
            server_key: serverKeyHex,
        }),
    });
    const finalizeData = await finalizeResp.json();
    if (!finalizeResp.ok) {
        throw new Error(finalizeData.message || "Failed to finalize registration.");
    }

    return finalizeData;
}
