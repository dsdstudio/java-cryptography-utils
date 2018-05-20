package net.dsdstudio.crypto;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.util.Base64;

/**
 * Created by bhkim on 2016. 7. 10..
 */
public class CryptoUtilTest {

    private final Pkcs10 pkcs10 = new Pkcs10();

    @BeforeClass
    public static void setUp() {
        Security.addProvider(new BouncyCastleProvider());
        System.out.println("register bouncy castle provider");
    }

    @Test
    public void aes256test() throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchProviderException, NoSuchPaddingException {
        String plainText = "우허허허허12312312312123";
        String secretKey = Base64.getEncoder().encodeToString("0123456789123456".getBytes());

        String encoded = CryptoUtil.aes256Encrypt(plainText, secretKey);
        System.out.println("original text :: " + plainText);
        System.out.println("encrypted :: " + encoded);

        Assert.assertEquals("plaintext 와 decrypted 는 같아야함", plainText, CryptoUtil.aes256Decrypt(encoded, secretKey));
        System.out.println("sha256hash :: " + CryptoUtil.sha256Hash(plainText.getBytes()));
    }

    @Test
    public void test() throws Exception {
        // 비대칭키 pub, prikey 생성
        KeyPair ecdsaKeyPair = generateKeyPair("ECDSA");

        X500Name subject = new X500NameBuilder()
                .addRDN(BCStyle.CN, "Test")
                .addRDN(BCStyle.O, "DSDSTUDIO")
                .addRDN(BCStyle.OU, "DSDSTUDIO")
                .build();
        PKCS10CertificationRequest pkcs10CertificationRequest = pkcs10.generatePKCS10(ecdsaKeyPair, "SHA512withECDSA", subject);
        String certString = pkcs10.pkcs10ToString(pkcs10CertificationRequest);
        System.out.println(certString);

        Files.write(Paths.get("test.certSigningRequest"), certString.getBytes());
    }

    private KeyPair generateKeyPair(String algorithm) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
