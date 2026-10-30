<?php
/**
 * Sample Banking Payment Processor (Vulnerable PHP).
 */

// Misuse 1: Static IV
$iv = "1234567890123456";

function processPayment($data, $rawKey) {
    global $iv;

    // Misuse 2: ECB mode
    $encrypted = openssl_encrypt($data, 'aes-128-ecb', $rawKey, 0);

    // Misuse 3: Legacy broken DES cipher
    $legacy = openssl_encrypt($data, 'des-cbc', substr($rawKey, 0, 8), 0, substr($iv, 0, 8));

    return [
        'encrypted' => $encrypted,
        'legacy' => $legacy
    ];
}

function generateOtp() {
    // Misuse 4: Weak PRNG (rand) used for banking OTP
    $otp = rand(100000, 999999);
    return strval($otp);
}

function postToCoreBanking($payload) {
    $ch = curl_init("https://core.bank.internal/api/settle");
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload));

    // Misuse 5: Disabled TLS certificate validation
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);

    // Misuse 6: Disabled hostname verification
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);

    $response = curl_exec($ch);
    curl_close($ch);
    return $response;
}
?>

