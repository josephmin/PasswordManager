import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

public class Crypto {
    private static final String AES_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final String RSA_ALGORITHM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final String SECURE_RANDOM_ALGORITHM = "NativePRNGNonBlocking";
    private static final int SIGNATURE_LENGTH = 256;

    public static byte[] aesEncrypt(Key aesKey, byte[] iv, byte[] bytesToEncrypt) {
        Cipher c;
        IvParameterSpec ivSpec;
        byte[] encryptedBytes = null;

        try {
            c = Cipher.getInstance(AES_ALGORITHM);
            ivSpec = new IvParameterSpec(iv);
            c.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
            encryptedBytes = c.doFinal(bytesToEncrypt);
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
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }

        return encryptedBytes;
    }

    public static byte[] aesDecrypt(Key aesKey, byte[] iv, byte[] bytesToDecrypt) {
        Cipher c;
        IvParameterSpec ivSpec;
        byte[] decryptedBytes = null;

        try {
            c = Cipher.getInstance(AES_ALGORITHM);
            ivSpec = new IvParameterSpec(iv);
            c.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
            decryptedBytes = c.doFinal(bytesToDecrypt);
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
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }

        return decryptedBytes;
    }

    public static byte[] keyWrap(Key pbKey, byte[] iv, Key keyToWrap) {
        Cipher c;
        IvParameterSpec ivSpec;
        byte[] wrappedKey = null;

        try {
            c = Cipher.getInstance(AES_ALGORITHM);
            ivSpec = new IvParameterSpec(iv);
            c.init(Cipher.WRAP_MODE, pbKey, ivSpec);
            wrappedKey = c.wrap(keyToWrap);
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
        }

        return wrappedKey;
    }

    public static byte[] keyWrap(PublicKey pub, Key keyToWrap) {
        Cipher c;
        byte[] wrappedKey = null;

        try {
            c = Cipher.getInstance(RSA_ALGORITHM);
            c.init(Cipher.WRAP_MODE, pub);
            wrappedKey = c.wrap(keyToWrap);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }

        return wrappedKey;
    }

    public static Key keyUnwrap(Key pbKey, byte[] iv, byte[] wrappedKey, String algorithm)
        throws IncorrectPasswordException {
        Cipher c;
        IvParameterSpec ivSpec;
        Key unwrappedKey = null;

        try {
            c = Cipher.getInstance(AES_ALGORITHM);
            ivSpec = new IvParameterSpec(iv);
            c.init(Cipher.UNWRAP_MODE, pbKey, ivSpec);
            unwrappedKey = c.unwrap(wrappedKey, algorithm, Cipher.SECRET_KEY);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            throw new IncorrectPasswordException();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

        return unwrappedKey;
    }

    public static Key keyUnwrap(PrivateKey priv, byte[] wrappedKey, String algorithm)
        throws InvalidKeyException {
        Cipher c;
        Key unwrappedKey = null;

        try {
            c = Cipher.getInstance(RSA_ALGORITHM);
            c.init(Cipher.UNWRAP_MODE, priv);
            unwrappedKey = c.unwrap(wrappedKey, algorithm, Cipher.SECRET_KEY);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            System.err.println("Invalid key. Exiting.");
            System.exit(1);
        }

        return unwrappedKey;
    }

    public static byte[] getHmac(Key hmacKey, byte[] body) {
        Mac m;
        byte[] hmacOutput = null;

        try {
            m = Mac.getInstance(HMAC_ALGORITHM);
            m.init(hmacKey);
            hmacOutput = m.doFinal(body);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        return hmacOutput;
    }

    public static boolean verifyHmac(Key hmacKey, byte[] hmac, byte[] body) {
        byte[] confirm = getHmac(hmacKey, body);
        return Arrays.equals(hmac, confirm);
    }

    public static byte[] sign (PrivateKey privKey, byte[] body) {
        SecureRandom rand;

        try {
            rand = SecureRandom.getInstance(SECURE_RANDOM_ALGORITHM); // if available, use /dev/urandom
        } catch (NoSuchAlgorithmException e) {
            rand = new SecureRandom(); // else use default
        }

        Signature s;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        try{
            s = Signature.getInstance(SIGNATURE_ALGORITHM);
            s.initSign(privKey, rand);
            s.update(body);
            baos.write(s.sign());
            baos.write(body);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return baos.toByteArray();
    }

    public static byte[] verify (PublicKey pubKey, byte[] signedBytes) {
        Signature s;
        boolean verified = false;
        byte[] signature;
        byte[] data = null;
        byte[] output = null;

        try {
            signature = Arrays.copyOfRange(signedBytes, 0, SIGNATURE_LENGTH);
            data = Arrays.copyOfRange(signedBytes, SIGNATURE_LENGTH, signedBytes.length);
            s = Signature.getInstance(SIGNATURE_ALGORITHM);
            s.initVerify(pubKey);
            s.update(data);
            verified = s.verify(signature);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }

        if (verified) {
            output = data;
        }

        return output;
    }
}