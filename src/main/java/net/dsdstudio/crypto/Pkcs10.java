package net.dsdstudio.crypto;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.StringWriter;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class Pkcs10 {
    public String pkcs10ToString(PKCS10CertificationRequest csr) {
        try {
            PemObject o = new PemObject("CERTIFICATE REQUEST", csr.getEncoded());
            StringWriter stringWriter = new StringWriter();
            PemWriter w = new PemWriter(stringWriter);
            w.writeObject(o);
            w.close();
            stringWriter.close();
            return stringWriter.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    public PKCS10CertificationRequest generatePKCS10(KeyPair pair, String signatureAlgorithm, X500Name subject) {
        PrivateKey priv = pair.getPrivate();
        PublicKey pub = pair.getPublic();

        PKCS10CertificationRequestBuilder pkcs10Builder = new JcaPKCS10CertificationRequestBuilder(subject, pub);
        try {
            return pkcs10Builder.build(new JcaContentSignerBuilder(signatureAlgorithm).setProvider("BC").build(priv));
        } catch (OperatorCreationException e) {
            throw new RuntimeException(e);
        }

    }
}
