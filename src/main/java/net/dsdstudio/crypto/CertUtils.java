package net.dsdstudio.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class CertUtils {
    public static final KeyPair generateKeyPair(String algorithm, int keySize) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
            generator.initialize(keySize);
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static final void writeCertFile(Path path, X509Certificate cert){
        try {
            String certString = "-----BEGIN CERTIFICATE-----\n" + Base64.getEncoder().encodeToString(cert.getEncoded())
                    + "\n-----END CERTIFICATE-----";
            Files.write(path, certString.getBytes());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    public static final X509Certificate readCert(Path path) {
        try (InputStream is = Files.newInputStream(path)){
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(is);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }
}
