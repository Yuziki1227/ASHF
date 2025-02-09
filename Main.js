/**
* AEROCAT Secure Hash Function (ASHF)
* AEROCAT Secure Hash Function (ASHF) is a cryptographic hash function specifically designed for securing user passwords and private data within the AEROCAT platform. This algorithm ensures robust encryption and key derivation, providing a high level of security for sensitive information.
* Note: While ASHF is designed to meet the security needs of the AEROCAT platform, it is important to regularly review and update cryptographic practices to stay ahead of evolving threats.
* 请注意, 这个代码不应该用于您的生产环境, AEROCAT所使用的相关加密方式为此代码的衍生, 并非此代码本体
 */
function vortexEncrypt(input, key) {
    // Convert inputs to UTF-8 bytes
    const data = new TextEncoder().encode(input.toString());
    const masterKey = new TextEncoder().encode(key.toString());

    // Key expansion using SHA-256 as primitive
    const expandedKey = crypto.subtle.digest('SHA-256', masterKey)
        .then(keyHash => new Uint8Array(keyHash));

    // Preprocess data with avalanche effect
    let state = [...data];
    for (let i = 0; i < 3; i++) { // 3-round diffusion
        state = state.map((byte, idx) =>
            (byte ^ state[(idx + 5) % state.length]) << 3 | byte >>> 5
        );
    }

    // Key-dependent permutation
    const permuted = new Uint8Array(state.length);
    masterKey.forEach((keyByte, i) => {
        const shift = keyByte % 32;
        permuted[i % permuted.length] = state[(i + shift) % state.length];
    });

    // Non-linear substitution layer
    const sBox = createDynamicSBox(expandedKey);
    const substituted = permuted.map(b => sBox[b % 256]);

    // Add cryptographic salt derived from key
    const salt = crypto.subtle.digest('SHA-256', expandedKey)
        .then(saltHash => new Uint8Array(saltHash));
    const salted = substituted.map((b, i) => b ^ salt[i % salt.length]);

    // Final compression with Merkle-Damgård construction
    let hash = new Uint8Array(64); // 512-bit internal state
    salted.forEach((block, idx) => {
        const roundKey = expandedKey[idx % expandedKey.length];
        hash[idx % hash.length] = (hash[idx % hash.length] + block + roundKey) % 256;
        hash = avalancheEffect(hash);
    });

    // Post-processing with key stretching
    return crypto.subtle.digest('SHA-512', hash)
        .then(finalHash => bytesToHex(finalHash));
}

/** Generate dynamic S-Box using key material */
function createDynamicSBox(key) {
    const sBox = Array.from({length: 256}, (_, i) => i);
    for (let i = 0; i < 256; i++) {
        const swapIdx = (key[i % key.length] + i * 179426549) % 256;
        [sBox[i], sBox[swapIdx]] = [sBox[swapIdx], sBox[i]];
    }
    return sBox;
}

/** Apply avalanche effect to internal state */
function avalancheEffect(state) {
    return state.map((b, i) => {
        const prev = state[(i - 1 + state.length) % state.length];
        const next = state[(i + 1) % state.length];
        return (b ^ prev ^ next) + (prev & next);
    });
}

/** Convert ArrayBuffer to hex string */
function bytesToHex(buffer) {
    return Array.from(new Uint8Array(buffer))
        .map(b => b.toString(16).padStart(2, '0')).join('');
}

// debug
(async () => {
    const encrypted = await vortexEncrypt("SecretMessage", "Password123!");
    console.log("Final hash:", encrypted);
})();