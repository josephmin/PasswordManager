import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.interfaces.RSAPublicKey;

public class KeyManager {
    private String dir;
    private String username;
    private char[] passwd;
    private File keyDir;
    private File publicKeyFile;
    private File privateKeyFile;
    private PublicKey publicKey;
    private PrivateKey privateKey;

    @SuppressWarnings("unused")
    private KeyManager() {
        // empty inaccessible constructor
    }

    public KeyManager(String username, char[] passwd) {
        this.username = username;
        this.passwd = passwd;
        this.dir = "keys/";
        keyDir = new File(this.dir);
        keyDir.mkdir();
        this.publicKeyFile = new File(this.dir + this.username + ".pub");
        this.privateKeyFile = new File(this.dir + this.username + ".key");
        this.publicKey = null;
        this.privateKey = null;
    }

    public void generateKeys() {
        KeyPairGenerator keygen = null;
        KeyPair keys;
        PublicKey publicKey;
        PrivateKey privateKey;

        try {
            keygen = KeyPairGenerator.getInstance("RSA");
            keygen.initialize(2048, new SecureRandom());
        } catch (NoSuchAlgorithmException e) { // impossible
            e.printStackTrace();
            System.exit(1);
        }

        if (keygen != null) {
            keys = keygen.generateKeyPair();
            publicKey = keys.getPublic();
            privateKey = keys.getPrivate();
            writePublicKey(publicKey);
            writePrivateKey(privateKey);
            System.out.println("Public key written to " + publicKeyFile.getPath());
            System.out.println("Private key written to " + privateKeyFile.getPath() + "\n");
        }
    }

    public void readPublicKey() throws FileNotFoundException {
        if (this.publicKeyFile.exists()) {
            ObjectInputStream ois;
            Object o;

            try {
                ois = new ObjectInputStream(new FileInputStream(publicKeyFile));
                o = ois.readObject();
                ois.close();
                if (o instanceof RSAPublicKey) {
                    publicKey = (PublicKey) o;
                } else {
                    System.err.println("The file " + publicKeyFile.getPath() + " is not a valid public key.\n");
                }
            } catch (IOException e) {
                e.printStackTrace();
                System.exit(1);
            } catch (ClassNotFoundException e) {
                e.printStackTrace();
                System.exit(1);
            }
        } else {
            throw new FileNotFoundException();
        }
    }

    public void readPrivateKey() throws IncorrectPasswordException, FileNotFoundException {
        if (this.privateKeyFile.exists()) {
            Crypto c = new Crypto(this.passwd);

            FileInputStream fis;
            byte[] inputBytes = null;

            try {
                fis = new FileInputStream(this.privateKeyFile);
                inputBytes = new byte[fis.available()];
                fis.read(inputBytes);
                fis.close();
                privateKey = KeyFactory.getInstance("RSA").generatePrivate(
                    new PKCS8EncodedKeySpec(
                        c.decryptKey(inputBytes)
                        )
                    );
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
                System.exit(1);
            } catch (InvalidKeySpecException e) {
                e.printStackTrace();
                System.exit(1);
            } catch (IOException e) {
                e.printStackTrace();
                System.exit(1);
            }
        } else {
            throw new FileNotFoundException();
        }
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public boolean exists() {
        return (publicKeyFile.exists() || privateKeyFile.exists());
    }

    // private helper methods
    private void writePublicKey(PublicKey key) {
        ObjectOutputStream oos;

        try {
            oos = new ObjectOutputStream(new FileOutputStream(this.privateKeyFile));
            oos.writeObject(key);
            oos.flush();
            oos.close();
        } catch (FileNotFoundException e) { // impossible
            e.printStackTrace();
            System.exit(1);
        } catch (IOException e) { //impossible
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void writePrivateKey(PrivateKey key) {
        Crypto c = new Crypto(this.passwd);
        byte[] encrypted = c.encryptKey(key);
        FileOutputStream output;

        try {
            output = new FileOutputStream(this.privateKeyFile);
            output.write(encrypted);
            output.flush();
            output.close();
        } catch (IOException e) {
            e.printStackTrace();
            System.exit(1);
        }
    }
}