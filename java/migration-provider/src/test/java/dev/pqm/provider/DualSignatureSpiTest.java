package dev.pqm.provider;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

final class DualSignatureSpiTest {
    @BeforeAll
    static void installProvider() {
        Security.addProvider(new PqmMigrationProvider());
    }

    @Test
    void signsAndRequiresBothSignatures() throws Exception {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        KeyPair rsaPair = rsa.generateKeyPair();
        KeyPairGenerator ed25519 = KeyPairGenerator.getInstance("Ed25519");
        KeyPair edPair = ed25519.generateKeyPair();
        DualPrivateKey privateKey = new DualPrivateKey(rsaPair.getPrivate(), "SHA256withRSA", edPair.getPrivate(), "Ed25519");
        DualPublicKey publicKey = new DualPublicKey(rsaPair.getPublic(), "SHA256withRSA", edPair.getPublic(), "Ed25519");
        byte[] message = "parallel migration signature".getBytes(StandardCharsets.UTF_8);

        Signature signer = Signature.getInstance("PQM-DUAL", PqmMigrationProvider.NAME);
        signer.initSign(privateKey, new SecureRandom());
        signer.update(message);
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance("PQM-DUAL", PqmMigrationProvider.NAME);
        verifier.initVerify(publicKey);
        verifier.update(message);
        assertTrue(verifier.verify(signature));

        signature[signature.length - 1] ^= 1;
        verifier.initVerify(publicKey);
        verifier.update(message);
        assertFalse(verifier.verify(signature));
    }
}
