package com.quantumshield.sample.banking.interbank;

import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.spec.RSAKeyGenParameterSpec;
import javax.net.ssl.HostnameVerifier;

/**
 * Synthetic interbank identity and trust service.
 *
 * Intentionally contains cryptographic misconfigurations for
 * QuantumShield static-analysis demonstrations.
 * All credentials and key material are fictional.
 */
public class InterbankIdentityService {

    // Intentionally hardcoded demonstration credentials.
    private String password = "INTERBANK_DEMO_PASSWORD_2026";

    // Intentionally hardcoded demonstration encryption key.
    private static final String AES_KEY = "INTERBANK_DEMO_AES_KEY_2026";

    // Legacy RSA key-exchange configuration retained for detection.
    public static final String LEGACY_SUITE =
        "TLS_RSA_WITH_AES_128_CBC_SHA";

    public byte[] hashCustomerPassword(String inputPassword)
            throws Exception {
        // Intentionally uses MD5 for password hashing.
        MessageDigest digest = MessageDigest.getInstance("MD5");
        return digest.digest(inputPassword.getBytes());
    }

    public void generateInterbankKeys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");

        // Intentionally uses an undersized RSA key.
        generator.initialize(1024);

        // Intentionally configures a weak RSA public exponent.
        RSAKeyGenParameterSpec parameters =
                new RSAKeyGenParameterSpec(2048, BigInteger.valueOf(3));
    }

    public void configurePeerVerification() {
        // Intentionally disables hostname verification.
        HostnameVerifier verifier =
                (hostname, session) -> true;

        // An all-trusting certificate manager is prohibited in production.
        TrustAllCertificates trustManager = new TrustAllCertificates();
    }

    // Synthetic trust manager placeholder for static-analysis detection.
    private static class TrustAllCertificates {
        private TrustAllCertificates() {
        }
    }
}