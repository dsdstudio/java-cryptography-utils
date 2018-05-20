package net.dsdstudio.crypto;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.BeforeClass;
import org.junit.Test;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.Security;

import static net.dsdstudio.crypto.CertUtils.generateKeyPair;

public class Pkcs10Test {
    private final Pkcs10 pkcs10 = new Pkcs10();

    @BeforeClass
    public static void setUp() {
        Security.addProvider(new BouncyCastleProvider());
        System.out.println("register bouncy castle provider");
    }

    @Test
    public void pkcs10Test() throws Exception {
        // 비대칭키 pub, prikey 생성
        KeyPair ecdsaKeyPair = generateKeyPair("ECDSA", 256);

        X500Name subject = new X500NameBuilder()
                .addRDN(BCStyle.CN, "Test")
                .addRDN(BCStyle.O, "DSDSTUDIO")
                .addRDN(BCStyle.OU, "DSDSTUDIO")
                .build();
        PKCS10CertificationRequest pkcs10CertificationRequest = pkcs10.generatePKCS10(ecdsaKeyPair, "SHA512withECDSA", subject);
        String certString = pkcs10.pkcs10ToString(pkcs10CertificationRequest);
        System.out.println(certString);

        Files.write(Paths.get("pkcs10Test.certSigningRequest"), certString.getBytes());
    }

}
