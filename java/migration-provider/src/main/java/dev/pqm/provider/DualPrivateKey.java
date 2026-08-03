package dev.pqm.provider;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.util.Objects;

public final class DualPrivateKey implements PrivateKey {
    private static final long serialVersionUID = 1L;
    private final PrivateKey classicalKey;
    private final PrivateKey postQuantumKey;
    private final String classicalSignatureAlgorithm;
    private final String postQuantumSignatureAlgorithm;

    public DualPrivateKey(
            PrivateKey classicalKey,
            String classicalSignatureAlgorithm,
            PrivateKey postQuantumKey,
            String postQuantumSignatureAlgorithm) {
        this.classicalKey = Objects.requireNonNull(classicalKey, "classicalKey");
        this.classicalSignatureAlgorithm = requireText(classicalSignatureAlgorithm, "classicalSignatureAlgorithm");
        this.postQuantumKey = Objects.requireNonNull(postQuantumKey, "postQuantumKey");
        this.postQuantumSignatureAlgorithm = requireText(postQuantumSignatureAlgorithm, "postQuantumSignatureAlgorithm");
    }

    public PrivateKey classicalKey() {
        return classicalKey;
    }

    public PrivateKey postQuantumKey() {
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
        return encodeKeys(classicalKey.getEncoded(), postQuantumKey.getEncoded());
    }

    static byte[] encodeKeys(byte[] first, byte[] second) {
        if (first == null || second == null) {
            return null;
        }
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream(first.length + second.length + 16);
            try (DataOutputStream output = new DataOutputStream(buffer)) {
                output.writeInt(0x50514d4b);
                output.writeInt(first.length);
                output.write(first);
                output.writeInt(second.length);
                output.write(second);
            }
            return buffer.toByteArray();
        } catch (IOException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private static String requireText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " is required");
        }
        return value;
    }
}
