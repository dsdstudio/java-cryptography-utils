package net.dsdstudio.crypto;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;
import java.util.Date;

public class CertificateTest {

    @BeforeClass
    public static void setUp() {
        Security.addProvider(new BouncyCastleProvider());
        System.out.println("register bouncy castle provider");
    }

    @Test
    public void 인증서생성테스트() throws Exception {
        KeyPair pair = CertUtils.generateKeyPair("RSA", 4096);

        SubjectPublicKeyInfo bcPk = SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded());

        X500Name issuer = new X500NameBuilder()
                .addRDN(BCStyle.C, "KR")
                .addRDN(BCStyle.O, "DSDSTUDIO")
                .addRDN(BCStyle.OU, "DSDSTUDIO Intermediate certificate")
                .addRDN(BCStyle.EmailAddress, "bhkim@dsdstudio.net")
                .build();
        X500Name subject = new X500NameBuilder()
                .addRDN(BCStyle.C, "KR")
                .addRDN(BCStyle.O, "DSDSTUDIO")
                .addRDN(BCStyle.OU, "DSDSTUDIO Intermediate certificate")
                .addRDN(BCStyle.EmailAddress, "bhkim@dsdstudio.net")
                .build();
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(3),
                new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30), new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 30)),
                subject, pair.getPublic());

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        builder.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(pair.getPublic()));
        builder.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(pair.getPublic()));

    }
}