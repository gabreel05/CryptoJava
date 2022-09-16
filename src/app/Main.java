package app;

import javax.crypto.*;
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

    public static final String AES = "AES";
    public static final String AES_CBC_PKCS_5_PADDING = "AES/CBC/PKCS5PADDING";

    public static void main(String[] args)
            throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
                BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        Scanner scanner = new Scanner(System.in);

        SecretKey secretKey = generateKey();
        IvParameterSpec iv = generateIV();

        String encrypted = encrypt(scanner.next(), secretKey, iv);
        String decrypted = decrypt(encrypted, secretKey, iv);

        out.println(encrypted);
        out.println(decrypted);
    }

    private static SecretKey generateKey() {
        byte[] bytes = new byte[16];
        new SecureRandom().nextBytes(bytes);
        return new SecretKeySpec(bytes, AES);
    }

    private static IvParameterSpec generateIV() {
        byte[] bytes = new byte[16];
        new SecureRandom().nextBytes(bytes);
        return new IvParameterSpec(bytes);
    }

    private static Cipher generateCipher(int encryptMode, SecretKey key, IvParameterSpec iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance(AES_CBC_PKCS_5_PADDING);
        cipher.init(encryptMode, key, iv);
        return cipher;
    }

    private static String encrypt(String message, SecretKey key, IvParameterSpec iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        byte[] bytes = generateCipher(Cipher.ENCRYPT_MODE, key, iv).doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(bytes);
    }

    private static String decrypt(String message, SecretKey key, IvParameterSpec iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        byte[] bytes = generateCipher(Cipher.DECRYPT_MODE, key, iv).doFinal(Base64.getDecoder().decode(message));
        return new String(bytes);
    }
}
