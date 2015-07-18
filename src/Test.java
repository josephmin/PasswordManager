import java.io.*;
import java.util.*;
import java.security.*;
import java.security.spec.*;

import javax.crypto.*;
import javax.crypto.spec.*;

public class Test {
    private static KeyPair alice;
    private static KeyPair bob;
    private static KeyManager km;

    public static void main(String[] args) {
        try {
            km = new KeyManager("Password".toCharArray());
            KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
            keygen.initialize(2048);
            alice = keygen.generateKeyPair();
            bob = keygen.generateKeyPair();

            writeTest();
            readTest();

            // Random rand = new Random();
            // byte[] b = new byte[16];
            // rand.nextBytes(b);

            // System.out.print("bytes: ");
            // for (byte a : b) {
            //     System.out.print(a + " ");
            // }
            // System.out.println("\n");

            // Signature s = Signature.getInstance("SHA256withRSA");
            // s.initSign(alice.getPrivate());
            // s.update(b);
            // byte[] signed = s.sign();

            // Signature s2 = Signature.getInstance("SHA256withRSA");
            // s2.initVerify(alice.getPublic());
            // s2.update(b);
            // System.out.println("verify: " + s2.verify(signed));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void writeTest() throws Exception {
        FileInputStream fis = new FileInputStream("files/test.txt");
        byte[] fileBytes = new byte[fis.available()];
        fis.read(fileBytes);

        System.out.print("File bytes: ");
        for (byte b : fileBytes) {
            System.out.print(b + " ");
        }
        System.out.println("\n");

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] encryptedBytes = Crypto.aesEncrypt(km.getAesKey(), km.getIV(), fileBytes);
        byte[] header = km.getHeader(bob.getPublic());
        baos.write(header);
        baos.write(encryptedBytes);
        byte[] signature = Crypto.sign(alice.getPrivate(), baos.toByteArray());

        FileOutputStream fos = new FileOutputStream("files/test.signed");
        fos.write(signature);
        fos.flush();
        fos.close();
    }

    private static void readTest() throws Exception {
        FileInputStream fis = new FileInputStream("files/test.signed");
        byte[] fileBytes = new byte[fis.available()];
        fis.read(fileBytes);
        if (Crypto.verify(alice.getPublic(), fileBytes)) {
            ByteArrayInputStream bais = new ByteArrayInputStream(fileBytes);
            bais.skip(256);
            byte[] header = new byte[16+256];
            bais.read(header);
            byte[] encryptedData = new byte[bais.available()];
            bais.read(encryptedData);

            KeyManager km = new KeyManager(bob.getPrivate(), header);
            byte[] unencrypted = Crypto.aesDecrypt(km.getAesKey(), km.getIV(), encryptedData);

            System.out.print("Unencrypted bytes: ");
            for (byte b : unencrypted) {
                System.out.print(b + " ");
            }
            System.out.println("\n");
        }

    }
}