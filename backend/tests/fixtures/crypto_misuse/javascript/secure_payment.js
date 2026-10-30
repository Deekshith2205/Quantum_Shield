/**
 * Sample Secure Banking Payment Service (Clean / Safe JavaScript).
 * Follows post-quantum and classical security standards:
 * - AES-256-GCM authenticated cipher
 * - CSPRNG (crypto.randomBytes)
 * - Dynamic environment secret retrieval
 * - Strong RSA parameters (4096 bits, standard exponent)
 */

const crypto = require('crypto');
const https = require('https');

function getVaultKey() {
    // Safe: loaded from protected environment
    const raw = process.env.CORE_BANK_SECRET;
    return raw ? Buffer.from(raw, 'hex') : crypto.randomBytes(32);
}

function processPaymentGcm(plaintextData) {
    const key = getVaultKey();
    // Safe: random 12-byte nonce
    const iv = crypto.randomBytes(12);

    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    let ciphertext = cipher.update(plaintextData, 'utf8', 'hex');
    ciphertext += cipher.final('hex');
    const authTag = cipher.getAuthTag();

    return {
        ciphertext,
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex')
    };
}

function generateSecureOtp() {
    // Safe: CSPRNG for OTP
    return crypto.randomInt(100000, 1000000).toString();
}

function generateRobustRsa() {
    // Safe: 4096-bit RSA key with standard public exponent
    return crypto.generateKeyPairSync('rsa', {
        modulusLength: 4096,
        publicExponent: 0x10001
    });
}

function createSecureAgent() {
    // Safe: strict certificate verification
    return new https.Agent({
        rejectUnauthorized: true
    });
}

module.exports = { processPaymentGcm, generateSecureOtp, generateRobustRsa, createSecureAgent };

