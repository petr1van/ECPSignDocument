package org.example;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Base64;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ECPElectronicSignatureBase64 {

    public static void main(String[] args) {
        try {
            FileInputStream keyFile = new FileInputStream("src/main/java/org/example/private_key.pem");
            PrivateKey privateKey = readPrivateKey(keyFile);
            keyFile.close();

            Signature signer = Signature.getInstance("SHA256withRSA", "BC");
            signer.initSign(privateKey);

            String document = "This is the content of the document that will be signed.";

            signer.update(document.getBytes());

            byte[] signature = signer.sign();

            // Конвертация подписи в базе64
            String base64Signature = Base64.getEncoder().encodeToString(signature);

            Files.write(Paths.get("signature.txt"), base64Signature.getBytes());

            System.out.println("Document signed successfully.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static PrivateKey readPrivateKey(FileInputStream keyFile) throws Exception {
        // Добавление провайдера Bouncy Castle
        BouncyCastleProvider provider = new BouncyCastleProvider();
        KeyStore keyStore = KeyStore.getInstance("PKCS8", provider);

        keyStore.load(keyFile, "private_key_password".toCharArray());

        return (PrivateKey) keyStore.getKey("private_key_alias", "private_key_password".toCharArray());
    }
}