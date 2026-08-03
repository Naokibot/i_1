package dev.pqm.provider;

import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.Signature;

final class AlgorithmResolver {
    private static final String[] PREFERRED_PROVIDERS = {"BC", "BCPQC"};

    private AlgorithmResolver() {
    }

    static Signature signature(String algorithm) throws GeneralSecurityException {
        GeneralSecurityException last = null;
        for (String provider : PREFERRED_PROVIDERS) {
            try {
                return Signature.getInstance(algorithm, provider);
            } catch (GeneralSecurityException exception) {
                last = exception;
            }
        }
        try {
            return Signature.getInstance(algorithm);
        } catch (GeneralSecurityException exception) {
            if (last != null) {
                exception.addSuppressed(last);
            }
            throw exception;
        }
    }

    static KeyPairGenerator keyPairGenerator(String algorithm) throws GeneralSecurityException {
        GeneralSecurityException last = null;
        for (String provider : PREFERRED_PROVIDERS) {
            try {
                return KeyPairGenerator.getInstance(algorithm, provider);
            } catch (GeneralSecurityException exception) {
                last = exception;
            }
        }
        try {
            return KeyPairGenerator.getInstance(algorithm);
        } catch (GeneralSecurityException exception) {
            if (last != null) {
                exception.addSuppressed(last);
            }
            throw exception;
        }
    }
}
