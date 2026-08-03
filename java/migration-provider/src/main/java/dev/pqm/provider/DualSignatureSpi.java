package dev.pqm.provider;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.SignatureSpi;

public final class DualSignatureSpi extends SignatureSpi {
    private static final int MAX_MESSAGE_SIZE = 64 * 1024 * 1024;
    private final ByteArrayOutputStream message = new ByteArrayOutputStream();
    private DualPrivateKey signingKey;
    private DualPublicKey verificationKey;

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (!(publicKey instanceof DualPublicKey dualPublicKey)) {
            throw new InvalidKeyException("PQM-DUAL verification requires DualPublicKey");
        }
        signingKey = null;
        verificationKey = dualPublicKey;
        message.reset();
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (!(privateKey instanceof DualPrivateKey dualPrivateKey)) {
            throw new InvalidKeyException("PQM-DUAL signing requires DualPrivateKey");
        }
        verificationKey = null;
        signingKey = dualPrivateKey;
        message.reset();
    }

    @Override
    protected void engineUpdate(byte value) throws SignatureException {
        ensureCapacity(1);
        message.write(value);
    }

    @Override
    protected void engineUpdate(byte[] values, int offset, int length) throws SignatureException {
        if (values == null || offset < 0 || length < 0 || offset + length > values.length) {
            throw new SignatureException("invalid update range");
        }
        ensureCapacity(length);
        message.write(values, offset, length);
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (signingKey == null) {
            throw new SignatureException("signature is not initialized for signing");
        }
        byte[] payload = message.toByteArray();
        try {
            Signature classical = AlgorithmResolver.signature(signingKey.classicalSignatureAlgorithm());
            classical.initSign(signingKey.classicalKey(), appRandom);
            classical.update(payload);
            Signature postQuantum = AlgorithmResolver.signature(signingKey.postQuantumSignatureAlgorithm());
            postQuantum.initSign(signingKey.postQuantumKey(), appRandom);
            postQuantum.update(payload);
            return new ParallelSignatureEnvelope(
                    signingKey.classicalSignatureAlgorithm(),
                    classical.sign(),
                    signingKey.postQuantumSignatureAlgorithm(),
                    postQuantum.sign()).encode();
        } catch (Exception exception) {
            throw new SignatureException("parallel signature failed", exception);
        } finally {
            clear(payload);
            message.reset();
        }
    }

    @Override
    protected boolean engineVerify(byte[] signatureBytes) throws SignatureException {
        if (verificationKey == null) {
            throw new SignatureException("signature is not initialized for verification");
        }
        byte[] payload = message.toByteArray();
        try {
            if (signatureBytes == null) {
                return false;
            }
            ParallelSignatureEnvelope envelope;
            try {
                envelope = ParallelSignatureEnvelope.decode(signatureBytes);
            } catch (IOException malformedEnvelope) {
                return false;
            }
            if (!envelope.classicalAlgorithm().equals(verificationKey.classicalSignatureAlgorithm())
                    || !envelope.postQuantumAlgorithm().equals(verificationKey.postQuantumSignatureAlgorithm())) {
                return false;
            }
            Signature classical = AlgorithmResolver.signature(envelope.classicalAlgorithm());
            classical.initVerify(verificationKey.classicalKey());
            classical.update(payload);
            if (!verifyCandidate(classical, envelope.classicalSignature())) {
                return false;
            }
            Signature postQuantum = AlgorithmResolver.signature(envelope.postQuantumAlgorithm());
            postQuantum.initVerify(verificationKey.postQuantumKey());
            postQuantum.update(payload);
            return verifyCandidate(postQuantum, envelope.postQuantumSignature());
        } catch (InvalidKeyException exception) {
            throw new SignatureException("parallel signature key initialization failed", exception);
        } catch (java.security.GeneralSecurityException exception) {
            throw new SignatureException("parallel signature provider failure", exception);
        } finally {
            clear(payload);
            message.reset();
        }
    }

    @Override
    @Deprecated
    protected void engineSetParameter(String parameter, Object value) {
        throw new UnsupportedOperationException("parameters are configured by the dual key");
    }

    @Override
    @Deprecated
    protected Object engineGetParameter(String parameter) {
        throw new UnsupportedOperationException("parameters are configured by the dual key");
    }

    private void ensureCapacity(int additional) throws SignatureException {
        if (additional > MAX_MESSAGE_SIZE - message.size()) {
            throw new SignatureException("message exceeds 64 MiB limit");
        }
    }

    private static boolean verifyCandidate(Signature verifier, byte[] candidate) {
        try {
            return verifier.verify(candidate);
        } catch (SignatureException invalidSignatureEncoding) {
            return false;
        }
    }

    private static void clear(byte[] value) {
        java.util.Arrays.fill(value, (byte) 0);
    }
}
