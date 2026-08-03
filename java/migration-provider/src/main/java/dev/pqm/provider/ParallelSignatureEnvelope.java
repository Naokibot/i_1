package dev.pqm.provider;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public record ParallelSignatureEnvelope(
        String classicalAlgorithm,
        byte[] classicalSignature,
        String postQuantumAlgorithm,
        byte[] postQuantumSignature) {
    private static final int MAGIC = 0x50514d53;
    private static final int VERSION = 1;
    private static final int MAX_ALGORITHM_BYTES = 256;
    private static final int MAX_SIGNATURE_BYTES = 1 << 20;

    public ParallelSignatureEnvelope {
        classicalSignature = classicalSignature.clone();
        postQuantumSignature = postQuantumSignature.clone();
    }

    @Override
    public byte[] classicalSignature() {
        return classicalSignature.clone();
    }

    @Override
    public byte[] postQuantumSignature() {
        return postQuantumSignature.clone();
    }

    public byte[] encode() {
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream(
                    classicalSignature.length + postQuantumSignature.length + 128);
            try (DataOutputStream output = new DataOutputStream(buffer)) {
                output.writeInt(MAGIC);
                output.writeInt(VERSION);
                writeBytes(output, classicalAlgorithm.getBytes(StandardCharsets.UTF_8), MAX_ALGORITHM_BYTES);
                writeBytes(output, classicalSignature, MAX_SIGNATURE_BYTES);
                writeBytes(output, postQuantumAlgorithm.getBytes(StandardCharsets.UTF_8), MAX_ALGORITHM_BYTES);
                writeBytes(output, postQuantumSignature, MAX_SIGNATURE_BYTES);
            }
            return buffer.toByteArray();
        } catch (IOException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    public static ParallelSignatureEnvelope decode(byte[] encoded) throws IOException {
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(encoded))) {
            if (input.readInt() != MAGIC || input.readInt() != VERSION) {
                throw new IOException("unsupported parallel signature envelope");
            }
            String classicalAlgorithm = new String(readBytes(input, MAX_ALGORITHM_BYTES), StandardCharsets.UTF_8);
            byte[] classicalSignature = readBytes(input, MAX_SIGNATURE_BYTES);
            String postQuantumAlgorithm = new String(readBytes(input, MAX_ALGORITHM_BYTES), StandardCharsets.UTF_8);
            byte[] postQuantumSignature = readBytes(input, MAX_SIGNATURE_BYTES);
            if (input.available() != 0) {
                throw new IOException("trailing data in parallel signature envelope");
            }
            return new ParallelSignatureEnvelope(
                    classicalAlgorithm,
                    classicalSignature,
                    postQuantumAlgorithm,
                    postQuantumSignature);
        }
    }

    private static void writeBytes(DataOutputStream output, byte[] value, int maximum) throws IOException {
        if (value.length > maximum) {
            throw new IOException("field exceeds maximum size");
        }
        output.writeInt(value.length);
        output.write(value);
    }

    private static byte[] readBytes(DataInputStream input, int maximum) throws IOException {
        int length = input.readInt();
        if (length < 0 || length > maximum) {
            throw new IOException("invalid field length");
        }
        byte[] value = input.readNBytes(length);
        if (value.length != length) {
            throw new IOException("truncated field");
        }
        return value;
    }

    @Override
    public boolean equals(Object other) {
        if (!(other instanceof ParallelSignatureEnvelope that)) {
            return false;
        }
        return classicalAlgorithm.equals(that.classicalAlgorithm)
                && postQuantumAlgorithm.equals(that.postQuantumAlgorithm)
                && Arrays.equals(classicalSignature, that.classicalSignature)
                && Arrays.equals(postQuantumSignature, that.postQuantumSignature);
    }

    @Override
    public int hashCode() {
        int result = classicalAlgorithm.hashCode();
        result = 31 * result + Arrays.hashCode(classicalSignature);
        result = 31 * result + postQuantumAlgorithm.hashCode();
        result = 31 * result + Arrays.hashCode(postQuantumSignature);
        return result;
    }
}
