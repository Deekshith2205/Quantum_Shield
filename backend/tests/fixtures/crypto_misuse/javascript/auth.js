/**
 * Sample Banking Authentication & Token Service (Vulnerable JavaScript).
 */

const crypto = require('crypto');

// Misuse 1: Hardcoded password
const password = "JwtSecretAdmin1234";

// Misuse 2: Hardcoded JWT Secret Key
const jwtSecret = "super_secret_jwt_token_2026_xyz";

// Misuse 3: Disabled TLS environment check
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

function hashPassword(plainPassword) {
    // Misuse 4: Insecure MD5 hash for password
    return crypto.createHash('md5').update(plainPassword).digest('hex');
}

function generateBankingKeys() {
    // Misuse 5: Small RSA key (1024 bits)
    // Misuse 6: Weak public exponent (e=3)
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 1024,
        publicExponent: 3
    });

    // Misuse 7: Hardcoded ECDH curve
    const ecdh = crypto.createECDH('secp256r1');

    return { publicKey, privateKey, ecdh };
}

module.exports = { hashPassword, generateBankingKeys };

