package net.dsdstudio.crypto;

import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Base64;

/**
 * Created by bhkim on 2016. 7. 10..
 */
public class CryptoUtilTest {
    @Test
    public void test() throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchProviderException, NoSuchPaddingException {
        String plainText = "우허허허허";
        String secretKey = Base64.getEncoder().encodeToString("0123456789123456".getBytes());

        String encoded = CryptoUtil.aes256Encrypt(plainText, secretKey);
        System.out.println("original text :: " + plainText);
        System.out.println("encrypted :: " + encoded);
        System.out.println("decrypted :: " + CryptoUtil.aes256Decrypt(encoded, secretKey));

        System.out.println("sha256hash :: " + CryptoUtil.sha256Hash(plainText.getBytes()));
    }
}
