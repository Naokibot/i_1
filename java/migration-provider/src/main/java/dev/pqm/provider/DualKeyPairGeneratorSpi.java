package dev.pqm.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public final class DualKeyPairGeneratorSpi extends KeyPairGeneratorSpi {
    private DualKeyGenParameterSpec parameters = DualKeyGenParameterSpec.migrationDefault();
    private SecureRandom random = new SecureRandom();

    @Override
    public void initialize(int keysize, SecureRandom random) {
        this.parameters = new DualKeyGenParameterSpec(
                "RSA", "RSASSA-PSS", Math.max(2048, keysize), "ML-DSA-65", "ML-DSA-65");
        this.random = random == null ? new SecureRandom() : random;
    }

    @Override
    public void initialize(AlgorithmParameterSpec parameters, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        if (!(parameters instanceof DualKeyGenParameterSpec dualParameters)) {
            throw new InvalidAlgorithmParameterException("DualKeyGenParameterSpec is required");
        }
        this.parameters = dualParameters;
        this.random = random == null ? new SecureRandom() : random;
    }

    @Override
    public KeyPair generateKeyPair() {
        try {
            KeyPairGenerator classical = AlgorithmResolver.keyPairGenerator(parameters.classicalKeyAlgorithm());
            if (parameters.classicalKeySize() > 0) {
                classical.initialize(parameters.classicalKeySize(), random);
            }
            KeyPairGenerator postQuantum = AlgorithmResolver.keyPairGenerator(parameters.postQuantumKeyAlgorithm());
            KeyPair classicalPair = classical.generateKeyPair();
            KeyPair postQuantumPair = postQuantum.generateKeyPair();
            return new KeyPair(
                    new DualPublicKey(
                            classicalPair.getPublic(),
                            parameters.classicalSignatureAlgorithm(),
                            postQuantumPair.getPublic(),
                            parameters.postQuantumSignatureAlgorithm()),
                    new DualPrivateKey(
                            classicalPair.getPrivate(),
                            parameters.classicalSignatureAlgorithm(),
                            postQuantumPair.getPrivate(),
                            parameters.postQuantumSignatureAlgorithm()));
        } catch (Exception exception) {
            throw new IllegalStateException("unable to generate dual key pair", exception);
        }
    }
}
