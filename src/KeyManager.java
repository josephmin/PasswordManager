import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class KeyManager {
    private static final int IV_LENGTH = 16;
    private static final int AES_KEY_LENGTH = 128; // Java does not support 192 or 256 bit AES keys
    private static final int HMAC_KEY_LENGTH = 256; // HMAC SHA256
    private static final int NUM_ITERATIONS = 32768; // (0.5)*(2^16)
    private static final int WRAPPED_AES_LENGTH = 32;
    private static final int RSA_WRAPPED_AES_LENGTH = 256;
    private static final int WRAPPED_HMAC_LENGTH = 48;
    private static final String SECURE_RANDOM_ALGORITHM = "NativePRNGNonBlocking";
    private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";

    private SecureRandom rand;
    private char[] password;
    private byte[] iv;
    private Key pbKey; // password-based key
    private Key aesKey; // AES key
    private Key hmacKey; // HMAC key
    private PublicKey publicKey;
    private PrivateKey privateKey;

    public KeyManager() {
        try {
            this.rand = SecureRandom.getInstance(SECURE_RANDOM_ALGORITHM); // if available, use /dev/urandom
        } catch (NoSuchAlgorithmException e) {
            this.rand = new SecureRandom(); // else use default
        }
    }

    public KeyManager(char[] password) {
        this();
        this.password = password;
        this.generateIV();
        this.generatePbKey();
        this.generateAesKey();
        this.generateHmacKey();
    }

    public KeyManager(char[] password, byte[] header) throws IncorrectPasswordException {
        this();
        this.password = password;
        this.iv = new byte[IV_LENGTH];
        byte[] kBytes = new byte[WRAPPED_AES_LENGTH];
        byte[] lBytes = new byte[WRAPPED_HMAC_LENGTH];
        ByteArrayInputStream bais = new ByteArrayInputStream(header);

        try {
            bais.read(this.iv);
            bais.read(kBytes);
            bais.read(lBytes);
        } catch (IOException e) {
            e.printStackTrace();
        }
        this.generatePbKey();
        this.aesKey = Crypto.keyUnwrap(this.pbKey, this.iv, kBytes, "AES");
        this.hmacKey = Crypto.keyUnwrap(this.pbKey, this.iv, lBytes, "HMAC");
    }

    public KeyManager(PrivateKey privKey, byte[] header) throws InvalidKeyException {
        this();
        this.iv = new byte[IV_LENGTH];
        byte[] aesKeyBytes = new byte[RSA_WRAPPED_AES_LENGTH];

        ByteArrayInputStream bais = new ByteArrayInputStream(header);

        try {
            bais.read(this.iv);
            bais.read(aesKeyBytes);
        } catch (IOException e) {
            e.printStackTrace();
        }

        this.privateKey = privKey;
        this.aesKey = Crypto.keyUnwrap(this.privateKey, aesKeyBytes, "AES");
        this.hmacKey = null;
    }

    public void generateRSAKeys() {
        KeyPairGenerator keygen;
        KeyPair kp = null;
        try {
            keygen = KeyPairGenerator.getInstance("RSA");
            keygen.initialize(2048, this.rand);
            kp = keygen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        if (kp != null) {
            this.publicKey = kp.getPublic();
            this.privateKey = kp.getPrivate();
        }
    }

    public static PublicKey readPublic(File publicKeyFile) {
        ObjectInputStream ois;
        Object o = null;
        PublicKey pk = null;
        try {
            ois = new ObjectInputStream(new FileInputStream(publicKeyFile));
            o = ois.readObject();
            ois.close();
        } catch (FileNotFoundException e) {
            pk = null;
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }

        if (o instanceof PublicKey) {
            pk = (PublicKey) o;
        }

        return pk;
    }

    public static PrivateKey readPrivate(File privateKeyFile) {
        ObjectInputStream ois;
        Object o = null;
        PrivateKey pk = null;
        try {
            ois = new ObjectInputStream(new FileInputStream(privateKeyFile));
            o = ois.readObject();
            ois.close();
        } catch (FileNotFoundException e) {
            pk = null;
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }

        if (o instanceof PrivateKey) {
            pk = (PrivateKey) o;
        }

        return pk;
    }

    public void setPublic(PublicKey pk) {
        this.publicKey = pk;
    }

    public PublicKey getPublic() {
        return this.publicKey;
    }

    public void setPrivate(PrivateKey pk) {
        this.privateKey = pk;
    }

    public PrivateKey getPrivate() {
        return this.privateKey;
    }

    public Key getPbKey() {
        return this.pbKey;
    }

    public Key getAesKey() {
        return this.aesKey;
    }

    public Key getHmacKey() {
        return this.hmacKey;
    }

    public byte[] getIV() {
        return this.iv;
    }

    public byte[] getHeader() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            baos.write(this.iv);
            baos.write(Crypto.keyWrap(this.pbKey, this.iv, this.aesKey));
            baos.write(Crypto.keyWrap(this.pbKey, this.iv, this.hmacKey));
        } catch (IOException e) {
            e.printStackTrace();
        }
        return baos.toByteArray();
    }

    public byte[] getHeader(PublicKey pubKey) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            baos.write(this.iv);
            baos.write(Crypto.keyWrap(pubKey, this.aesKey));
        } catch (IOException e) {
            e.printStackTrace();
        }
        return baos.toByteArray();
    }

    private void generatePbKey() {
        SecretKeyFactory factory;
        KeySpec pwSpec;
        try {
            factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
            pwSpec = new PBEKeySpec(this.password, this.iv, NUM_ITERATIONS, AES_KEY_LENGTH);
            this.pbKey = new SecretKeySpec(factory.generateSecret(pwSpec).getEncoded(), "AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

    private void generateAesKey() {
        KeyGenerator keyGen;
        try {
            keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(AES_KEY_LENGTH, this.rand);
            this.aesKey = keyGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    private void generateHmacKey() {
        KeyGenerator keyGen;
        try {
            keyGen = KeyGenerator.getInstance("HmacSHA256");
            keyGen.init(HMAC_KEY_LENGTH, this.rand);
            this.hmacKey = keyGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    private void generateIV() {
        this.iv = new byte[IV_LENGTH];
        this.rand.nextBytes(iv);
    }
}