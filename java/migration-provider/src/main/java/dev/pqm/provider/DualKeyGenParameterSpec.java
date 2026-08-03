package dev.pqm.provider;

import java.security.spec.AlgorithmParameterSpec;
import java.util.Objects;

public record DualKeyGenParameterSpec(
        String classicalKeyAlgorithm,
        String classicalSignatureAlgorithm,
        int classicalKeySize,
        String postQuantumKeyAlgorithm,
        String postQuantumSignatureAlgorithm) implements AlgorithmParameterSpec {

    public DualKeyGenParameterSpec {
        Objects.requireNonNull(classicalKeyAlgorithm, "classicalKeyAlgorithm");
        Objects.requireNonNull(classicalSignatureAlgorithm, "classicalSignatureAlgorithm");
        Objects.requireNonNull(postQuantumKeyAlgorithm, "postQuantumKeyAlgorithm");
        Objects.requireNonNull(postQuantumSignatureAlgorithm, "postQuantumSignatureAlgorithm");
        if (classicalKeySize < 2048 && classicalKeyAlgorithm.equalsIgnoreCase("RSA")) {
            throw new IllegalArgumentException("RSA key size must be at least 2048 bits");
        }
    }

    public static DualKeyGenParameterSpec migrationDefault() {
        return new DualKeyGenParameterSpec("RSA", "RSASSA-PSS", 3072, "ML-DSA-65", "ML-DSA-65");
    }
}
