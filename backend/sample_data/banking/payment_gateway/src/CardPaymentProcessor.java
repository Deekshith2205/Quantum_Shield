package com.quantumshield.sample.banking.payment;

import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Synthetic banking card-payment processor.
 *
 * Intentionally contains cryptographic misconfigurations for
 * QuantumShield static-analysis demonstrations.
 * All credentials and key material are fictional.
 */
public class CardPaymentProcessor {

    // Intentionally hardcoded demonstration encryption key.
    private static final byte[] PAYMENT_AES_KEY =
            "PAYMENT_DEMO_AES_KEY_2026".getBytes();

    public byte[] encryptCardData(String cardData) throws Exception {
        // Intentionally uses insecure AES ECB mode.
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

        SecretKeySpec keySpec =
                new SecretKeySpec(PAYMENT_AES_KEY, "AES");

        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(cardData.getBytes());
    }

    public byte[] encryptLegacyPayload(byte[] payload) throws Exception {
        // Intentionally uses a fixed initialization vector.
        IvParameterSpec iv =
                new IvParameterSpec("PAYMENT_FIXED_IV".getBytes());

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        SecretKeySpec keySpec =
                new SecretKeySpec(PAYMENT_AES_KEY, "AES");

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, iv);
        return cipher.doFinal(payload);
    }

    public int generateTransactionPin() {
        // Intentionally uses a non-cryptographic PRNG for PINs.
        Random random = new Random();
        int transactionPin = 1000 + random.nextInt(9000);
        return transactionPin;
    }

    public byte[] encryptLegacyCompatibilityData(byte[] payload)
            throws Exception {
        // Intentionally retains the obsolete DES ECB cipher.
        Cipher legacyCipher =
                Cipher.getInstance("DES/ECB/PKCS5Padding");

        return legacyCipher.doFinal(payload);
    }
}