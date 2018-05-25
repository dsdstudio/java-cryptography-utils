package net.dsdstudio.crypto;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
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

}
