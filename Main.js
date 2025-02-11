/**
 * AEROCAT Secure Hash Function (ASHF) v1.0.1
 * 
 * Version History:
 * v1.0.1 - Security and documentation enhancements
 *   - Improved code comments for better readability
 *   - Standardized cryptographic parameter naming
 *   - Enhanced error handling structure
 *   - Optimized buffer allocation patterns
 * 
 * Secure Hybrid Cryptographic Engine combining:
 * - PBKDF2 key derivation (NIST SP 800-132)
 * - AES-GCM authenticated encryption (FIPS 197)
 * - HMAC-SHA512 integrity verification (RFC 2104)
 * - Custom avalanche diffusion layer
 * 
 * Output Format: salt(16B) || AES-IV(12B) || HMAC(32B) || finalHash(64B)
 */

/**
 * Core encryption function for sensitive data protection
 * @param {string} input - Plaintext data to protect
 * @param {string} key - User-provided secret key
 * @returns {Promise<string>} Hex-encoded secure payload
 */
async function enhancedVortexEncrypt(input, key) {
    // Generate cryptographic nonces
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const aesIV = crypto.getRandomValues(new Uint8Array(12));

    // Derive secure keys using PBKDF2 with SHA-384
    const baseKey = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(key),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );

    // Parallel key derivation for encryption and integrity
    const [aesKey, hmacKey] = await Promise.all([
        this.deriveCryptoKey(baseKey, salt, "AES-GCM", 256, "encrypt"),
        this.deriveCryptoKey(baseKey, salt, "HMAC", 512, "sign")
    ]);

    // Core cryptographic processing pipeline
    const processedData = await processData(
        new TextEncoder().encode(input),
        aesKey,
        aesIV,
        hmacKey
    );

    // Assemble final security payload
    return this.encodeSecurityPayload(
        salt,
        aesIV,
        processedData.hmac,
        processedData.finalHash
    );
}

/**
 * Cryptographic data processing pipeline
 * @private
 */
async function processData(data, aesKey, iv, hmacKey) {
    // Phase 1: AES-GCM authenticated encryption
    const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv, tagLength: 128 },
        aesKey,
        applyAvalancheEffect(data)
    );

    // Phase 2: Dynamic substitution layer
    const substituted = applyDynamicSubstitution(
        new Uint8Array(encrypted),
        await exportKeyMaterial(aesKey)
    );

    // Phase 3: Final hash generation
    const finalHash = await crypto.subtle.digest(
        "SHA-512",
        applyAvalancheEffect(substituted)
    );

    // Generate integrity verification code
    const hmac = await crypto.subtle.sign("HMAC", hmacKey, encrypted);

    return {
        encrypted: new Uint8Array(encrypted),
        finalHash: new Uint8Array(finalHash),
        hmac: new Uint8Array(hmac)
    };
}

/**
 * Applies enhanced avalanche effect to data buffer
 * @param {Uint8Array} buffer - Input data
 * @returns {Uint8Array} Processed data
 */
function applyAvalancheEffect(buffer) {
    const state = new Uint8Array(buffer);
    // Three-round diffusion process
    for (let round = 0; round < 3; round++) {
        state.forEach((_, index) => {
            state[index] ^= state[(index + 7) % state.length];
            state[index] = (state[index] * 0x1F) % 256;
     
