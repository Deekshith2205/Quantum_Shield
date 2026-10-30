<?php
/**
 * Sample Banking Authentication & Crypto Module (Vulnerable PHP).
 */

// Misuse 1: Hardcoded credentials
$password = "DatabaseAdminPass2026!";

// Misuse 2: Hardcoded API secret
$api_key = "live_secret_bank_key_php_12345678";

function hashUserCredentials($plainPassword, $token) {
    // Misuse 3: MD5 password hashing
    $hashedPassword = md5($plainPassword);

    // Misuse 4: SHA-1 for authentication token
    $tokenDigest = sha1($token);

    return [
        'pwd_hash' => $hashedPassword,
        'token_hash' => $tokenDigest
    ];
}

function generateBankingKeyPairs() {
    // Misuse 5: Small RSA key (1024 bits)
    // Misuse 6: Weak exponent (3)
    $config = [
        'private_key_bits' => 1024,
        'rsa_exponent' => 3,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
    ];
    $res = openssl_pkey_new($config);

    // Misuse 7: Hardcoded ECDH curve
    $ecConfig = [
        'curve_name' => 'secp256r1',
        'private_key_type' => OPENSSL_KEYTYPE_EC,
    ];
    $ecRes = openssl_pkey_new($ecConfig);

    return [$res, $ecRes];
}
?>

