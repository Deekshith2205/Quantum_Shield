<?php
/**
 * Sample Secure Banking Payment Service (Clean / Safe PHP).
 * Follows modern security and post-quantum guidelines:
 * - AES-256-GCM AEAD encryption with random 96-bit nonce
 * - Cryptographically secure randomness (random_bytes)
 * - password_hash() using Bcrypt / Argon2id
 * - Strict TLS certificate and hostname validation
 * - Dynamic environment secret retrieval
 */

function getVaultKey() {
    $secretHex = getenv('CORE_BANK_SECRET');
    return $secretHex ? hex2bin($secretHex) : random_bytes(32);
}

function processSecurePayment($plaintext) {
    $key = getVaultKey();
    // Safe: random 12-byte IV for GCM
    $iv = random_bytes(12);
    $tag = "";

    $ciphertext = openssl_encrypt(
        $plaintext,
        'aes-256-gcm',
        $key,
        OPENSSL_RAW_DATA,
        $iv,
        $tag
    );

    return [
        'ciphertext' => bin2hex($ciphertext),
        'iv' => bin2hex($iv),
        'tag' => bin2hex($tag)
    ];
}

function secureHashPassword($plainPassword) {
    // Safe: modern password hashing with salted bcrypt
    return password_hash($plainPassword, PASSWORD_BCRYPT);
}

function callExternalBankService($data) {
    $ch = curl_init("https://core.bank.internal/api/settle");
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));

    // Safe: strict TLS verification
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);

    $res = curl_exec($ch);
    curl_close($ch);
    return $res;
}
?>

