package dev.pqm.provider;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

final class ParallelSignatureEnvelopeSecurityTest {
    @Test
    void roundTripsDefensiveCopies() throws Exception {
        byte[] classical = {1, 2, 3};
        byte[] postQuantum = {4, 5, 6};
        ParallelSignatureEnvelope envelope =
                new ParallelSignatureEnvelope("SHA256withRSA", classical, "ML-DSA-65", postQuantum);
        classical[0] = 99;
        postQuantum[0] = 99;

        ParallelSignatureEnvelope decoded = ParallelSignatureEnvelope.decode(envelope.encode());
        assertArrayEquals(new byte[] {1, 2, 3}, decoded.classicalSignature());
        assertArrayEquals(new byte[] {4, 5, 6}, decoded.postQuantumSignature());

        byte[] returned = decoded.classicalSignature();
        returned[0] = 88;
        assertArrayEquals(new byte[] {1, 2, 3}, decoded.classicalSignature());
    }

    @Test
    void rejectsTruncationTrailingDataAndInvalidLengths() {
        byte[] encoded = new ParallelSignatureEnvelope(
                        "SHA256withRSA", new byte[] {1, 2, 3}, "ML-DSA-65", new byte[] {4, 5, 6})
                .encode();

        for (int length = 0; length < encoded.length; length++) {
            byte[] truncated = Arrays.copyOf(encoded, length);
            assertThrows(IOException.class, () -> ParallelSignatureEnvelope.decode(truncated));
        }

        byte[] trailing = Arrays.copyOf(encoded, encoded.length + 1);
        trailing[trailing.length - 1] = 1;
        assertThrows(IOException.class, () -> ParallelSignatureEnvelope.decode(trailing));

        byte[] negativeLength = encoded.clone();
        ByteBuffer.wrap(negativeLength).putInt(8, -1);
        assertThrows(IOException.class, () -> ParallelSignatureEnvelope.decode(negativeLength));

        byte[] oversizedLength = encoded.clone();
        ByteBuffer.wrap(oversizedLength).putInt(8, 257);
        assertThrows(IOException.class, () -> ParallelSignatureEnvelope.decode(oversizedLength));
    }

    @Test
    void rejectsUnknownMagicAndVersion() {
        byte[] encoded = new ParallelSignatureEnvelope(
                        "SHA256withRSA", new byte[] {1}, "ML-DSA-65", new byte[] {2})
                .encode();
        byte[] badMagic = encoded.clone();
        badMagic[0] ^= 1;
        assertThrows(IOException.class, () -> ParallelSignatureEnvelope.decode(badMagic));

        byte[] badVersion = encoded.clone();
        ByteBuffer.wrap(badVersion).putInt(4, 2);
        assertThrows(IOException.class, () -> ParallelSignatureEnvelope.decode(badVersion));
    }
}
