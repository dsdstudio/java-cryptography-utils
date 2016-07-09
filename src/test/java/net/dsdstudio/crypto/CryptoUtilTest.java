package net.dsdstudio.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Base64;

/**
 * Created by bhkim on 2016. 7. 10..
 */
public class CryptoUtilTest {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void test() throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchProviderException, NoSuchPaddingException {
        String plainText = "우허허허허";
        String key = Base64.getEncoder().encodeToString("0123456789123456".getBytes());

        String encoded = encrypt(plainText, key);
        System.out.println("original text :: " + plainText);
        System.out.println("encrypted :: " + encoded);
        System.out.println("decrypted :: " + decrypt(encoded, key));

        System.out.println("sha256hash :: " + sha256Hash(plainText.getBytes()));
    }


    private String decrypt(String hexEncodedText, String secretKey) {
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

    private String encrypt(String text, String secretKey) {
        try {
            String iv = secretKey.substring(0, 16);
            byte[] keyData = Base64.getDecoder().decode(secretKey);

            SecretKey secureKey = new SecretKeySpec(keyData, "AES");

            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.ENCRYPT_MODE, secureKey,
                    new IvParameterSpec(iv.getBytes()));

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
