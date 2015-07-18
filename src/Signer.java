import java.security.Signature;
import java.security.PrivateKey;
import java.security.PublicKey;

public class Signer {
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    private Signature sign;
    private PublicKey recipient;
    private PrivateKey sender;

}