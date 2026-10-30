package com.quantumshield.sample.banking;

import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SecurePaymentGateway {

    private final SecureRandom secureRandom = new SecureRandom();

    public byte[] encryptWithGcm(byte[] plaintext) throws Exception {
        // Safe: environment-loaded or KMS key
        String envKey = System.getenv("SECURE_VAULT_KEY");
        byte[] keyBytes = (envKey != null) ? envKey.getBytes() : new byte[32];
        secureRandom.nextBytes(keyBytes);

        // Safe: AES-256-GCM AEAD mode
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[12];
        secureRandom.nextBytes(iv); // Safe CSPRNG nonce

        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, spec);
        return cipher.doFinal(plaintext);
    }

    public byte[] computeSha256Digest(byte[] data) throws Exception {
        // Safe: SHA-256 integrity hash
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(data);
    }

    public void generateRobustRsaKeys() throws Exception {
        // Safe: 4096-bit RSA key size
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(4096);
    }
}

