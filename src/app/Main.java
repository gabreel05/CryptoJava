package app;

import javax.crypto.*;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Scanner;

import static java.lang.System.*;

public class Main {

    public static final String DES = "DES";
    public static final String DES_ECB_PKCS_5_PADDING = "DES/ECB/PKCS5PADDING";

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        Scanner scanner = new Scanner(System.in);

        SecretKey secretKey = generateKey();

        String encrypted = encrypt(scanner.next(), secretKey);
        String decrypted = decrypt(encrypted, secretKey);

        out.println(encrypted);
        out.println(decrypted);
    }

    private static SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(DES);
        return keyGenerator.generateKey();
    }

    private static Cipher generateCipher(int encryptMode, SecretKey key)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance(DES_ECB_PKCS_5_PADDING);
        cipher.init(encryptMode, key);
        return cipher;
    }

    private static String encrypt(String message, SecretKey key)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
                IllegalBlockSizeException, BadPaddingException {
        byte[] bytes = generateCipher(Cipher.ENCRYPT_MODE, key).doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(bytes);
    }

    private static String decrypt(String message, SecretKey key)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
                IllegalBlockSizeException, BadPaddingException {
        byte[] bytes = generateCipher(Cipher.DECRYPT_MODE, key).doFinal(Base64.getDecoder().decode(message));
        return new String(bytes);
    }
}
