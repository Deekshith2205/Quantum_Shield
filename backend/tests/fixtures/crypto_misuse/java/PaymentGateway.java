package com.quantumshield.sample.banking;

import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class PaymentGateway {

    // Misuse 1: Hardcoded AES encryption key
    private static final byte[] AES_KEY = "bank_aes_secret_12345678".getBytes();

    public byte[] encryptCreditCard(String cardData) throws Exception {
        // Misuse 2: Insecure ECB mode
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(AES_KEY, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(cardData.getBytes());
    }

    public byte[] encryptWithStaticIv(byte[] plaintext) throws Exception {
        // Misuse 3: Static Initialization Vector
        IvParameterSpec ivSpec = new IvParameterSpec("0123456789abcdef".getBytes());
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(AES_KEY, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        return cipher.doFinal(plaintext);
    }

    public int generateTransactionPin() {
        // Misuse 4: Weak PRNG (java.util.Random) for security PIN
        Random rand = new Random();
        return 1000 + rand.nextInt(9000);
    }

    public byte[] legacyEncrypt(byte[] data) throws Exception {
        // Misuse 5: Broken legacy DES cipher
        Cipher desCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        return desCipher.doFinal(data);
    }
}

