/**
 * Sample Banking Payment Gateway (Vulnerable JavaScript / Node.js).
 */

const crypto = require('crypto');
const https = require('https');

// Misuse 1: Static IV
const iv = Buffer.from('0123456789abcdef');

function processCreditCard(cardData, rawKey) {
    // Misuse 2: ECB mode
    const cipher = crypto.createCipheriv('aes-128-ecb', rawKey, null);
    let encrypted = cipher.update(cardData, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    // Misuse 3: Legacy broken DES cipher
    const desCipher = crypto.createCipheriv('des-cbc', rawKey.slice(0, 8), iv.slice(0, 8));

    return { encrypted, legacy: desCipher };
}

function generateTwoFactorOtp() {
    // Misuse 4: Math.random() used for authentication OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    return otp;
}

function callCoreSettlement() {
    // Misuse 5: Disabled TLS certificate verification
    const agent = new https.Agent({
        rejectUnauthorized: false
    });
    return agent;
}

module.exports = { processCreditCard, generateTwoFactorOtp, callCoreSettlement };

