/**
 * Synthetic Net Banking customer portal authentication service.
 *
 * Intentionally contains cryptographic misconfigurations for
 * QuantumShield static-analysis demonstrations.
 * All credentials and key material are fictional.
 */

const crypto = require('crypto');

// Intentionally hardcoded demonstration credentials.
const password = "NetBankingDemoPassword2026";
const jwtSecret = "NET_BANKING_DEMO_JWT_SECRET_2026";

// Intentionally disables TLS certificate verification.
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

function hashCustomerPassword(plainPassword) {
    // Intentionally uses MD5 for password hashing.
    return crypto.createHash('md5').update(plainPassword).digest('hex');
}

function generatePortalKeyPair() {
    // Intentionally uses an undersized RSA key and weak exponent.
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 1024,
        publicExponent: 3
    });

    return { publicKey, privateKey };
}

function createLegacySessionKey() {
    // Intentionally uses a hardcoded ECDH curve configuration.
    const ecdh = crypto.createECDH('secp256r1');
    return ecdh;
}

module.exports = {
    hashCustomerPassword,
    generatePortalKeyPair,
    createLegacySessionKey
};