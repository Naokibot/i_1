import javax.crypto.Cipher;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;

public final class LegacyCrypto {
    public static void main(String[] args) throws Exception {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(1024);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        MessageDigest digest = MessageDigest.getInstance("SHA-1");
        System.out.println(cipher + " " + digest + " " + rsa);
    }
}
