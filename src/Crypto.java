import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Crypto {
    private static final int SALT_LENGTH = 16;
    private static final int IV_LENGTH = 16;
    private static final String CHECKSUM = "SUCCESS";
    private static final int CHECKSUM_LENGTH = CHECKSUM.getBytes().length;
    private static final int KEY_LENGTH = 128; //Java does not support 192 or 256 bit AES keys
    private static final int NUM_ITERATIONS = 32768; // (0.5)*(2^16)
    private static final String ALGORITHM = "AES/CTR/PKCS5Padding";

    private Cipher c;
    private char[] password;
    private byte[] salt;
    private Key aesKey;

    public Crypto(char[] passwd) {
        this.password = passwd;
        try {
            c = Cipher.getInstance(ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }
    }

    private void encryptInit() {
        this.salt = this.generateSalt();
        this.aesKey = this.generateKey();
        try {
            c.init(Cipher.ENCRYPT_MODE, this.aesKey);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    private void decryptInit(byte[] salt, IvParameterSpec ivSpec) {
        this.salt = salt;
        this.aesKey = this.generateKey();
        try {
            c.init(Cipher.DECRYPT_MODE, this.aesKey, ivSpec);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }

    public byte[] encryptKey(PrivateKey key) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] output = null;
        this.encryptInit();

        try {
            baos.write(this.salt);
            baos.write(c.getIV());
            byte[] checksumBytes = c.doFinal(CHECKSUM.getBytes());
            System.out.println(checksumBytes.length);
            baos.write(checksumBytes);
            baos.write(c.doFinal(key.getEncoded()));
            output = baos.toByteArray();
            baos.close();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
        return output;
    }

    public byte[] decryptKey(byte[] encodedBytes) throws IncorrectPasswordException {
        ByteArrayInputStream bais = new ByteArrayInputStream(encodedBytes);

        byte[] salt = new byte[SALT_LENGTH];
        byte[] iv = new byte[IV_LENGTH];
        byte[] checksum = new byte[CHECKSUM_LENGTH];
        byte[] encodedKey = null;
        byte[] decryptedKey = null;

        try {
            bais.read(salt);
            bais.read(iv);
            bais.read(checksum);
            encodedKey = new byte[bais.available()];
            bais.read(encodedKey);
        } catch (IOException e) { //should be impossible
            e.printStackTrace();
        }

        IvParameterSpec ivSpec;

        try {
            ivSpec = new IvParameterSpec(iv);
            this.decryptInit(salt, ivSpec);
            c.doFinal(encodedKey);

            if (Arrays.equals(c.doFinal(checksum), CHECKSUM.getBytes())) {
                decryptedKey = c.doFinal(encodedKey);
            } else {
                throw new IncorrectPasswordException();
            }
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e){
            e.printStackTrace();
        }

        return decryptedKey;
    }

    public byte[] encryptBytes(byte[] unencryptedBytes) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] encryptedBytes = null;
        this.encryptInit();

        try {
            baos.write(this.salt);
            baos.write(c.getIV());
            baos.write(c.doFinal(unencryptedBytes));
            encryptedBytes = baos.toByteArray();
            baos.close();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
        return encryptedBytes;
    }

    public byte[] unencryptBytes(byte[] encryptedBytes) {
        ByteArrayInputStream bais = new ByteArrayInputStream(encryptedBytes);

        this.salt = new byte[SALT_LENGTH];
        byte[] iv = new byte[IV_LENGTH];
        byte[] encrypted = null;
        byte[] decrypted = null;

        try {
            bais.read(this.salt);
            bais.read(iv);
            encrypted = new byte[bais.available()];
            bais.read(encrypted);
            bais.close();
        } catch (IOException e) { //should be impossible
            e.printStackTrace();
        }

        Cipher c;
        IvParameterSpec ivSpec;
        this.aesKey = this.generateKey();

        try {
            c = Cipher.getInstance(ALGORITHM);
            ivSpec = new IvParameterSpec(iv);
            c.init(Cipher.DECRYPT_MODE, this.aesKey, ivSpec);
            decrypted = c.doFinal(encrypted);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e){
            e.printStackTrace();
        }

        return decrypted;
    }

    private Key generateKey() {
        SecretKeyFactory factory;
        Key key = null;
        KeySpec pwSpec;
        try {
            factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            pwSpec = new PBEKeySpec(this.password, this.salt, NUM_ITERATIONS, KEY_LENGTH);
            key = new SecretKeySpec(factory.generateSecret(pwSpec).getEncoded(), "AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }

        return key;
    }

    private byte[] generateSalt() {
        SecureRandom rand = null;
        byte[] salt = new byte[SALT_LENGTH];

        try {
            rand = SecureRandom.getInstance("NativePRNGNonBlocking"); // if available, use /dev/urandom
        } catch (NoSuchAlgorithmException e) {
            rand = new SecureRandom(); // else use default
        }
        if (rand != null) {
            rand.nextBytes(salt);
        }

        return salt;
    }
}