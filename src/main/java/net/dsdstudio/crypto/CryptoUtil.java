package net.dsdstudio.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Base64;

public class CryptoUtil {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static String aes256Decrypt(String hexEncodedText, String secretKey) {
        try {
            String iv = secretKey.substring(0, 16);
            byte[] keyData = Base64.getDecoder().decode(secretKey);

            SecretKey secureKey = new SecretKeySpec(keyData, "AES");
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.DECRYPT_MODE, secureKey, new IvParameterSpec(iv.getBytes("UTF-8")));

            byte[] byteStr = Hex.decode(hexEncodedText);
            return new String(c.doFinal(byteStr), "UTF-8");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String aes256Encrypt(String text, String secretKey) {
        try {
            String iv = secretKey.substring(0, 16);
            byte[] keyData = Base64.getDecoder().decode(secretKey);

            SecretKey secureKey = new SecretKeySpec(keyData, "AES");

            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.ENCRYPT_MODE, secureKey, new IvParameterSpec(iv.getBytes()));

            byte[] encrypted = c.doFinal(text.getBytes("UTF-8"));
            return Hex.toHexString(encrypted);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String sha256Hash(byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA256");
            return Hex.toHexString(md.digest(input));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
