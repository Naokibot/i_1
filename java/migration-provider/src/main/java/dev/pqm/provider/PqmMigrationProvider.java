package dev.pqm.provider;

import java.security.Provider;

public final class PqmMigrationProvider extends Provider {
    public static final String NAME = "PQM";
    private static final long serialVersionUID = 1L;

    public PqmMigrationProvider() {
        super(NAME, "0.2", "Explicit parallel classical and post-quantum migration primitives");
        put("Signature.PQM-DUAL", DualSignatureSpi.class.getName());
        put("Alg.Alias.Signature.PARALLEL-SIGNATURE", "PQM-DUAL");
        put("KeyPairGenerator.PQM-DUAL", DualKeyPairGeneratorSpi.class.getName());
    }
}
