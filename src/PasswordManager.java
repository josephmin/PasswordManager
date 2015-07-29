import java.io.ByteArrayInputStream;
import java.io.Console;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.InputMismatchException;
import java.util.Scanner;

public class PasswordManager {
    private static final File KEY_DIR = new File("keys");
    private static final File FILE_DIR = new File("files");
    private static final int HEADER_LENGTH = 96; //iv + aesKey + hmacKey
    private static final int SIGN_HEADER_LENGTH = 16 + 256;
    private static final int HMAC_LENGTH = 32;

    private Scanner scan;
    private Console cons;
    private KeyManager km;
    private PasswordDatabase pd;
    private File dbFile;
    private boolean modified;

    public PasswordManager() {
        scan = new Scanner(System.in);
        cons = System.console();
    }

    public static void help() {
        System.out.println("init: Create a new database.\n" +
            "keygen: Generate public/private RSA keys.\n" +
            "load: Load a password database.\n" +
            "sign: Sign a database.\n" +
            "verify: Verify a signed database.\n");
    }

    public void init() {
        String dbName = null;
        boolean valid = false;
        while (!valid) {
            System.out.print("Enter name to save database: ");
            dbName = scan.nextLine();
            if (dbName.length() == 0) {
                System.out.println("Name cannot be null.\n");
            } else {
            this.dbFile = new File(FILE_DIR.getPath() + "/" + dbName + ".db");
                if (this.dbFile.exists()) {
                    System.out.print("A database named '" + dbName + "' already exists.\nOverwrite (y/n)? ");
                    String overwrite = scan.nextLine();
                    if (overwrite.equalsIgnoreCase("y")) {
                        valid = true;
                    } else if (!overwrite.equalsIgnoreCase("n")) {
                        System.out.println("That's not valid.");
                    }
                } else {
                    valid = true;
                }
            }
        }
        char[] password = this.createPassword();
        this.km = new KeyManager(password);
        this.pd = new PasswordDatabase();
        KEY_DIR.mkdir();
        FILE_DIR.mkdir();
        System.out.println("New password database '" + dbName + "' has been created.\n");

        this.menu();
    }

    private char[] createPassword() {
        boolean valid = false;
        char[] password = null;
        char[] confirm = null;

        while(!valid) {
            System.out.print("Create a password: ");
            password = cons.readPassword();
            if (password.length < 16) {
                System.out.println("Password should be at least 16 characters long.\n");
            } else {
                System.out.print("Confirm password: ");
                confirm = cons.readPassword();
                if (Arrays.equals(password, confirm)) {
                    valid = true;
                } else {
                    System.out.println("Passwords do not match. Please try again.");
                }
            }
        }

        return password;
    }

    public void load() {
        System.out.print("Enter name of database to load: ");
        String dbName = scan.nextLine();
        this.dbFile = new File(FILE_DIR.getPath() + "/" + dbName + ".db");
        FileInputStream fis;
        byte[] header = new byte[HEADER_LENGTH];
        byte[] hmac = new byte[HMAC_LENGTH];
        byte[] dbBytes = null;

        try {
            fis = new FileInputStream(this.dbFile);
            fis.read(header);
            fis.read(hmac);
            dbBytes = new byte[fis.available()];
            fis.read(dbBytes);
            fis.close();
        } catch (FileNotFoundException e) {
            System.err.println("That password database does not exist. Exiting.");
            System.exit(1);
        } catch (IOException e) {
            e.printStackTrace();
        }

        System.out.println("Loading '" + this.dbFile.getPath() + "'");
        System.out.print("Password: ");
        char[] password = this.cons.readPassword();

        try {
            km = new KeyManager(password, header);
        } catch (IncorrectPasswordException e) {
            System.err.println("Error: Incorrect password or corrupt database. Exiting.");
            System.exit(1);
        }

        if (Crypto.verifyHmac(km.getHmacKey(), hmac, dbBytes)) {
            pd = new PasswordDatabase(Crypto.aesDecrypt(km.getAesKey(), km.getIV(), dbBytes));
            System.out.println();
            this.menu();
        } else {
            System.err.println("Error: Incorrect password or corrupt database. Exiting.");
            System.exit(1);
        }
    }

    public void keygen() {
        //TODO: password encrypt key
        System.out.println("Generating public/private RSA key pair.");
        String keyName = null;
        boolean valid = false;
        while (!valid) {
            System.out.print("Enter file in which to save the keys: ");
            keyName = scan.nextLine();
            if (keyName.length() == 0) {
                System.out.println("File name should not be null.\n");
            } else {
                valid = true;
            }
        }

        File pubFile = null;
        File privFile = null;
        if (keyName != null) {
            pubFile = new File(KEY_DIR.getPath() + "/" + keyName + ".pub");
            privFile = new File(KEY_DIR.getPath() + "/" + keyName + ".priv");
        } else {
            System.err.println("There was an error creating the RSA public/private keys.");
            System.exit(1);
        }

        if (pubFile.exists() || privFile.exists()) {
            System.out.print("An RSA key for '" + keyName + "' already exists. Overwrite (y/n)? ");
            String overwrite = scan.nextLine();
            if (overwrite.equalsIgnoreCase("n") || !overwrite.equalsIgnoreCase("y")) {
                System.exit(0);
            }
        }
        ObjectOutputStream pubOutput;
        ObjectOutputStream privOutput;

        if (km == null) {
            km = new KeyManager();
        }
        km.generateRSAKeys();

        try {
            pubOutput = new ObjectOutputStream(
            new FileOutputStream(pubFile));
            privOutput = new ObjectOutputStream(
            new FileOutputStream(privFile));
            pubOutput.writeObject(km.getPublic());
            pubOutput.flush();
            pubOutput.close();
            privOutput.writeObject(km.getPrivate());
            privOutput.flush();
            privOutput.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        System.out.println("\nPublic key written to '" + pubFile.getPath() + "'");
        System.out.println("Private key written to '" + privFile.getPath() + "'\n");
        System.exit(0);
    }

    public void sign() {
        String dbName = null;
        boolean exist = false;
        while (!exist) {
            System.out.print("Enter database to sign: ");
            dbName = scan.nextLine();
            this.dbFile = new File(FILE_DIR.getPath() + "/" + dbName + ".db");
            if (this.dbFile.exists()) {
                exist = true;
                System.out.println("Loading '" + this.dbFile.getPath() + "'");
            } else {
                System.out.println("'" + dbName + "' does not exist. Please confirm the name and try again.\n");
            }
        }

        System.out.print("Password: ");
        char[] password = cons.readPassword();

        FileInputStream fis;
        byte[] header = new byte[HEADER_LENGTH];
        byte[] hmac = new byte[HMAC_LENGTH];
        byte[] dbBytes = null;

        try {
            fis = new FileInputStream(this.dbFile);
            fis.read(header);
            fis.read(hmac);
            dbBytes = new byte[fis.available()];
            fis.read(dbBytes);
            this.km = new KeyManager(password, header);
            fis.close();
            if (Crypto.verifyHmac(this.km.getHmacKey(), hmac, dbBytes)) {
                this.pd = new PasswordDatabase(Crypto.aesDecrypt(this.km.getAesKey(), this.km.getIV(), dbBytes));
            } else {
                throw new IncorrectPasswordException();
            }
        } catch (IncorrectPasswordException e) {
            System.err.println("Error: Incorrect password or corrupt database. Exiting.");
            System.exit(1);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        File privateKeyFile;
        boolean valid = false;
        while (!valid) {
            System.out.print("Enter path to your private key: ");
            privateKeyFile = new File(scan.nextLine());
            if (privateKeyFile.exists()) {
                this.km.setPrivate(KeyManager.readPrivate(privateKeyFile));
                if (km.getPrivate() != null) {
                    valid = true;
                } else {
                    System.out.println("'" + privateKeyFile.getPath() + "' is not a valid RSA private key.\n");
                }
            } else {
                System.out.println("'" + privateKeyFile.getPath() + "' does not exist. Check the path and try again.\n");
            }
        }

        File publicKeyFile;
        valid = false;
        while (!valid) {
            System.out.print("Enter path to recepient's public key: ");
            publicKeyFile = new File(scan.nextLine());
            if (publicKeyFile.exists()) {
                this.km.setPublic(KeyManager.readPublic(publicKeyFile));
                if (km.getPublic() != null) {
                    valid = true;
                } else {
                    System.out.println("'" + publicKeyFile.getPath() + "' is not a valid RSA public key.\n");
                }
            } else {
                System.out.println("'" + publicKeyFile.getPath() + "' does not exist. Check the path and try again.\n");
            }
        }

        byte[] signedHeader = km.getHeader(km.getPublic());
        byte[] encryptedBytes = Crypto.aesEncrypt(km.getAesKey(), km.getIV(), pd.getBytes());

        ByteBuffer bb = ByteBuffer.allocate(signedHeader.length + encryptedBytes.length);
        bb.put(signedHeader);
        bb.put(encryptedBytes);
        byte[] signature = Crypto.sign(km.getPrivate(), bb.array());
        FileOutputStream fos;
        try {
            fos = new FileOutputStream(FILE_DIR.getPath() + "/" + dbName + ".signed");
            fos.write(signature);
            fos.flush();
            fos.close();
            System.out.println("Signed database has been written to '" + FILE_DIR.getPath() + "/" + dbName + ".signed'");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void verify() {
        boolean exist = false;
        String dbPath;
        File dbFile = null;
        while (!exist) {
            System.out.print("Enter path to signed database: ");
            dbPath = scan.nextLine();
            if (dbPath.length() > 0) {
                dbFile = new File(dbPath);
                if (dbFile.exists() && dbFile.isFile()) {
                    exist = true;
                } else {
                    System.out.println("'" + dbFile.getPath() + "' is not a valid file. Check path and try again.\n");
                }
            } else {
                System.out.println("Invalid path.");
            }
        }

        File privateKeyFile;
        PrivateKey privateKey = null;
        boolean valid = false;
        while (!valid) {
            System.out.print("Enter path to your private key: ");
            privateKeyFile = new File(scan.nextLine());
            if (privateKeyFile.exists()) {
                privateKey = KeyManager.readPrivate(privateKeyFile);
                if (privateKey != null) {
                    valid = true;
                } else {
                    System.out.println("'" + privateKeyFile.getPath() + "' is not a valid RSA private key.\n");
                }
            } else {
                System.out.println("'" + privateKeyFile.getPath() + "' does not exist. Check the path and try again.\n");
            }
        }

        File publicKeyFile;
        PublicKey publicKey = null;
        valid = false;
        while (!valid) {
            System.out.print("Enter path to sender's public key: ");
            publicKeyFile = new File(scan.nextLine());
            if (publicKeyFile.exists()) {
                publicKey = KeyManager.readPublic(publicKeyFile);
                if (publicKey != null) {
                    valid = true;
                } else {
                    System.out.println("'" + publicKeyFile.getPath() + "' is not a valid RSA public key.\n");
                }
            } else {
                System.out.println("'" + publicKeyFile.getPath() + "' does not exist. Check the path and try again.\n");
            }
        }

        FileInputStream fis;
        byte[] fileBytes = null;
        try {
            fis = new FileInputStream(dbFile);
            fileBytes = new byte[fis.available()];
            fis.read(fileBytes);
            fis.close();
            byte[] data = Crypto.verify(publicKey, fileBytes);
            byte[] header = new byte[SIGN_HEADER_LENGTH];
            byte[] dbBytes;
            if (data != null) {
                try {
                    ByteArrayInputStream bais = new ByteArrayInputStream(data);
                    bais.read(header);
                    dbBytes = new byte[bais.available()];
                    bais.read(dbBytes);

                    this.km = new KeyManager(privateKey, header);
                    this.pd = new PasswordDatabase(Crypto.aesDecrypt(this.km.getAesKey(), this.km.getIV(), dbBytes));
                    System.out.println("The database has been successfully verified and loaded.\n");
                    this.menu();
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (InvalidKeyException e) {
                    e.printStackTrace();
                }
            } else {
                System.out.println("The signed database cannot be verified. Exiting.");
                System.exit(1);
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void menu() {
        while(true) { //infinite loop until exit
            System.out.println("What would you like to do?\n" +
                "1. List entries\n" +
                "2. View an entry\n" +
                "3. Add a new entry\n" +
                "4. Modify an entry\n" +
                "5. Delete an entry\n" +
                "6. Change password\n" +
                "7. Save and exit\n" +
                "8. Exit\n");
            System.out.print("Your choice (1-8): ");
            int choice = 0;
            try {
                choice = scan.nextInt();
            } catch (InputMismatchException e) {
                choice = -1;
            }

            scan.nextLine(); // eat new line

            switch (choice) {
                case 1: this.list(); break;
                case 2: this.get(); break;
                case 3: this.add(); break;
                case 4: this.modify(); break;
                case 5: this.delete(); break;
                case 6: this.changePassword(); break;
                case 7: this.save();
                case 8: this.exit(); break;
                default: System.out.println("Invalid choice.\n");
            }

            System.out.print("Press Enter to continue ");
            scan.nextLine();
            System.out.println();
        }
    }

    private void list() {
        String[] aliases = pd.getAliases();

        if (aliases.length == 0) {
            System.out.println("There are currently no entries.\n");
        } else {
            int i = 1;
            for (String s : aliases) {
                System.out.println((i++) + ". " + s);
            }

            System.out.print("\nEnter entry number to view (0 to go back to the menu): ");
            int choice = 0;
            try {
                choice = scan.nextInt();
            } catch (InputMismatchException e) {
                System.out.println("Invalid choice. Going back to the main menu.\n");
            }
            scan.nextLine();
            if (choice > 0 && choice < i) {
                this.get(aliases[choice - 1]);
            } else if (choice != 0) {
                System.out.println("Invalid choice. Going back to the main menu.\n");
            }
        }
    }

    private void get() {
        System.out.print("Enter alias of entry to view: ");
        String alias = scan.nextLine();
        this.get(alias);
    }

    private void get(String alias) {
        String[] entry;

        try {
            entry = pd.getEntry(alias);
            System.out.println("Alias: " + alias + "\n" +
                "Username: " + entry[0] + "\n" +
                "Password: " + entry[1] + "\n" +
                "Comment: " + entry[2] + "\n");
        } catch (EntryDoesNotExistException e) {
            System.out.println("An entry for '" + alias + "' does not exist.\n");
        }
    }

    private void add() {
        String alias = null;
        String[] entry = new String[3];

        try {
            System.out.print("Enter alias for entry: ");
            alias = scan.nextLine();
            System.out.print("Enter username: ");
            entry[0] = scan.nextLine();
            System.out.print("Enter password: ");
            entry[1] = scan.nextLine();
            System.out.print("Enter a comment: ");
            entry[2] = scan.nextLine();
            System.out.println();

            pd.addEntry(alias, entry);
            modified = true;
            System.out.println("Entry has been successfully added.");
        } catch (EntryAlreadyExistsException e) {
            System.out.println("An entry for '" + alias + "' already exists.\n");
        } catch (InvalidEntryException e) {
            System.out.println("That entry is invalid.\n");
        }
    }

    private void modify() {
        String alias = null;
        String[] entry;
        String in;
        System.out.print("Enter alias to modify: ");
        alias = scan.nextLine();

        try{
            entry = pd.getEntry(alias);
            System.out.print("New username (" + entry[0] + "): ");
            in = scan.nextLine();
            if (in.length() > 0) {
                entry[0] = in;
            }
            System.out.print("New password (" + entry[1] + "): ");
            in = scan.nextLine();
            if (in.length() > 0) {
                entry[1] = in;
            }
            System.out.print("New comment (" + entry[2] + "): ");
            in = scan.nextLine();
            if (in.length() > 0) {
                entry[2] = in;
            }
            pd.modifyEntry(alias, entry);
            modified = true;
            System.out.println();
        } catch (EntryDoesNotExistException e) {
            System.out.println("An entry for '" + alias + "' does not exist.\n");
        }
    }

    private void delete() {
        String alias = null;
        System.out.print("Enter alias to delete: ");
        alias = scan.nextLine();

        try {
            pd.removeEntry(alias);
            System.out.println("'" + alias + "' has been deleted.\n");
            modified = true;
        } catch (EntryDoesNotExistException e) {
            System.out.println("An entry for '" + alias + "' does not exist.\n");
        }
    }

    private void changePassword() {
        System.out.println("Creating a new password.");
        char[] pwd = this.createPassword();
        km = new KeyManager(pwd);

        System.out.println("\nPassword has been successfully changed.\n");
        modified = true;
    }

    private void save() {
        if (km.getHmacKey() == null) {
            System.out.println("This database does not have a password. Create a password now.\n");
            char[] pwd = this.createPassword();
            km = new KeyManager(pwd);
            String dbName = null;
            boolean valid = false;
            while (!valid) {
                System.out.print("Enter name to save this database: ");
                dbName = scan.nextLine();
                if (dbName.length() > 0) {
                    this.dbFile = new File(FILE_DIR.getPath() + "/" + dbName + ".db");
                    if (this.dbFile.exists()) {
                        System.out.print("A database named '" + dbName + "' already exists.\n" +
                            "Overwrite (y/n)? ");
                        String overwrite = scan.nextLine();
                        if (overwrite.equalsIgnoreCase("y")) {
                            valid = true;
                        } else if (!overwrite.equalsIgnoreCase("n")) {
                            System.out.println("That's not valid.\n");
                        }
                    }
                }
            }
        }

        byte[] header = km.getHeader();
        byte[] encryptedBytes = Crypto.aesEncrypt(km.getAesKey(), km.getIV(), pd.getBytes());
        byte[] hmac = Crypto.getHmac(km.getHmacKey(), encryptedBytes);

        FileOutputStream fos;
        try {
            fos = new FileOutputStream(this.dbFile.getPath());
            fos.write(header);
            fos.write(hmac);
            fos.write(encryptedBytes);
            fos.flush();
            fos.close();
            System.out.println("Database has been written to '" + this.dbFile.getPath() + "'");
            modified = false;
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void exit() {
        if (modified) {
            System.out.print("You have unsaved changes. Save changes (y/n)? ");
            String save = scan.next();
            scan.nextLine();
            if (save.equals("y")) {
                this.save();
            }
        }
        scan.close();
        System.exit(0);
    }
}