package dev.pqm.provider;

import java.security.PublicKey;
import java.util.Objects;

public final class DualPublicKey implements PublicKey {
    private static final long serialVersionUID = 1L;
    private final PublicKey classicalKey;
    private final PublicKey postQuantumKey;
    private final String classicalSignatureAlgorithm;
    private final String postQuantumSignatureAlgorithm;

    public DualPublicKey(
            PublicKey classicalKey,
            String classicalSignatureAlgorithm,
            PublicKey postQuantumKey,
            String postQuantumSignatureAlgorithm) {
        this.classicalKey = Objects.requireNonNull(classicalKey, "classicalKey");
        this.classicalSignatureAlgorithm = requireText(classicalSignatureAlgorithm, "classicalSignatureAlgorithm");
        this.postQuantumKey = Objects.requireNonNull(postQuantumKey, "postQuantumKey");
        this.postQuantumSignatureAlgorithm = requireText(postQuantumSignatureAlgorithm, "postQuantumSignatureAlgorithm");
    }

    public PublicKey classicalKey() {
        return classicalKey;
    }

    public PublicKey postQuantumKey() {
        return postQuantumKey;
    }

    public String classicalSignatureAlgorithm() {
        return classicalSignatureAlgorithm;
    }

    public String postQuantumSignatureAlgorithm() {
        return postQuantumSignatureAlgorithm;
    }

    @Override
    public String getAlgorithm() {
        return "PQM-DUAL";
    }

    @Override
    public String getFormat() {
        return "PQM-DUAL";
    }

    @Override
    public byte[] getEncoded() {
        return DualPrivateKey.encodeKeys(classicalKey.getEncoded(), postQuantumKey.getEncoded());
    }

    private static String requireText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " is required");
        }
        return value;
    }
}
