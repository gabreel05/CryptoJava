package app;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;

import static java.lang.System.*;

public class Main {

    public static final int TAG_LENGTH_BIT = 128;
    public static final int IV_LENGTH_BYTE = 16;

    private Main() {}

    public static final String AES = "AES";
    public static final String AES_GCM_NoPadding = "AES/GCM/NoPadding";

    public static void main(String[] args)
            throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
                BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        Scanner scanner = new Scanner(System.in);

        SecretKey secretKey = generateKey();
        GCMParameterSpec iv = generateIV();

        String encrypted = encrypt(scanner.nextLine(), secretKey, iv);
        String decrypted = decrypt(encrypted, secretKey, iv);

        out.println(encrypted);
        out.println(decrypted);
    }

    private static SecretKey generateKey() {
        byte[] bytes = new byte[16];
        new SecureRandom().nextBytes(bytes);
        return new SecretKeySpec(bytes, AES);
    }

    private static GCMParameterSpec generateIV() {
        byte[] bytes = new byte[IV_LENGTH_BYTE];
        new SecureRandom().nextBytes(bytes);
        return new GCMParameterSpec(TAG_LENGTH_BIT, bytes);
    }

    private static Cipher generateCipher(int encryptMode, SecretKey key, GCMParameterSpec iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance(AES_GCM_NoPadding);
        cipher.init(encryptMode, key, iv);
        return cipher;
    }

    private static String encrypt(String message, SecretKey key, GCMParameterSpec iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        byte[] bytes = generateCipher(Cipher.ENCRYPT_MODE, key, iv).doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(bytes);
    }

    private static String decrypt(String message, SecretKey key, GCMParameterSpec iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        byte[] bytes = generateCipher(Cipher.DECRYPT_MODE, key, iv).doFinal(Base64.getDecoder().decode(message));
        return new String(bytes);
    }
}
