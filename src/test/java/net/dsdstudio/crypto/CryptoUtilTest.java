package net.dsdstudio.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.Security;
import java.util.Base64;

/**
 * Created by bhkim on 2016. 7. 10..
 */
public class CryptoUtilTest {
    @BeforeClass
    public static void setUp() {
        Security.addProvider(new BouncyCastleProvider());
        System.out.println("register bouncy castle provider");
    }

    @Test
    public void aes256test() {
        String plainText = "우허허허허12312312312123";
        String secretKey = Base64.getEncoder().encodeToString("0123456789123456".getBytes());

        String encoded = CryptoUtil.aes256Encrypt(plainText, secretKey);
        System.out.println("original text :: " + plainText);
        System.out.println("encrypted :: " + encoded);

        Assert.assertEquals("plaintext 와 decrypted 는 같아야함", plainText, CryptoUtil.aes256Decrypt(encoded, secretKey));
        System.out.println("sha256hash :: " + CryptoUtil.sha256Hash(plainText.getBytes()));
    }
}
