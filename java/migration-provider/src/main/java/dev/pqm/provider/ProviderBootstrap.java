package dev.pqm.provider;

import java.lang.reflect.InvocationTargetException;
import java.security.Provider;
import java.security.Security;

public final class ProviderBootstrap {
    private ProviderBootstrap() {
    }

    public static void install() {
        if (Security.getProvider(PqmMigrationProvider.NAME) == null) {
            Security.addProvider(new PqmMigrationProvider());
        }
        installReflectively("org.bouncycastle.jce.provider.BouncyCastleProvider");
        installReflectively("org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider");
    }

    private static void installReflectively(String className) {
        try {
            Class<?> type = Class.forName(className);
            Provider provider = (Provider) type.getConstructor().newInstance();
            if (Security.getProvider(provider.getName()) == null) {
                Security.addProvider(provider);
            }
        } catch (ClassNotFoundException ignored) {
            // The migration provider can still operate with algorithms supplied by another provider.
        } catch (ReflectiveOperationException exception) {
            Throwable cause = exception instanceof InvocationTargetException
                    ? ((InvocationTargetException) exception).getTargetException()
                    : exception;
            throw new IllegalStateException("Unable to install provider " + className, cause);
        }
    }
}
