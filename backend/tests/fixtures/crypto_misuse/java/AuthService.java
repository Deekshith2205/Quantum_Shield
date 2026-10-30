package com.quantumshield.sample.banking;

import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.spec.RSAKeyGenParameterSpec;
import javax.net.ssl.HostnameVerifier;

public class AuthService {

    // Misuse 1: Hardcoded password
    private String password = "EnterpriseSecret2026!";

    // Misuse 2: Hardcoded RSA Key Exchange Suite
    public static final String CIPHER_SUITE = "TLS_RSA_WITH_AES_128_CBC_SHA";

    public byte[] hashUserPassword(String inputPassword) throws Exception {
        // Misuse 3: MD5 used for password hashing
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(inputPassword.getBytes());
    }

    public void generateSubordinateKeys() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        // Misuse 4: Small RSA key size (1024 bits)
        kpg.initialize(1024);

        // Misuse 5: Weak public exponent (e=3)
        RSAKeyGenParameterSpec spec = new RSAKeyGenParameterSpec(2048, BigInteger.valueOf(3));
    }

    public void configureInsecureTls() {
        // Misuse 6: Disabled Hostname Verification
        HostnameVerifier verifier = (hostname, session) -> true;

        // Misuse 7: Disabled Certificate Verification (TrustAllCertificates)
        TrustAllCertificates trustManager = new TrustAllCertificates();
    }

    private static class TrustAllCertificates {}
}

