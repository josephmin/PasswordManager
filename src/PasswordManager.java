import java.io.Console;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.util.Arrays;
import java.util.Scanner;

public class PasswordManager {
    private static final File KEY_DIR = new File("keys");
    private static final File FILE_DIR = new File("files");
    private static final int HEADER_LENGTH = 96; //iv + aesKey + hmacKey
    private static final int HMAC_LENGTH = 32;

    private Scanner scan;
    private Console cons;
    private KeyManager km;
    private PasswordDatabase pd;
    private String dbName;
    private boolean modified;

    public PasswordManager() {
        scan = new Scanner(System.in);
        cons = System.console();
    }

    public static void help() {
        System.out.println("init: Create a new database.\n" +
            "keygen: Generate public/private RSA keys.\n" +
            "sign: Sign a database.\n" +
            "verify: Verify a signed database.\n");
    }

    public void init() {
        System.out.print("Enter name to save database: ");
        this.dbName = scan.nextLine();
        char[] password = this.createPassword();
        this.km = new KeyManager(password);
        this.pd = new PasswordDatabase();
        KEY_DIR.mkdir();
        FILE_DIR.mkdir();
        System.out.println("New password database '" + this.dbName + "' has been created.\n");

        this.menu();
    }

    private char[] createPassword() {
        boolean valid = false;
        char[] password = null;
        char[] confirm = null;

        while(!valid) {
            System.out.print("Create a password: ");
            password = cons.readPassword();
            System.out.print("Confirm password: ");
            confirm = cons.readPassword();
            if (Arrays.equals(password, confirm)) {
                valid = true;
            } else {
                System.out.println("Passwords do not match. Please try again.");
            }
        }

        return password;
    }

    public void load(String fileName) {
        this.dbName = fileName;
        FileInputStream fis;
        byte[] header = new byte[HEADER_LENGTH];
        byte[] hmac = new byte[HMAC_LENGTH];
        byte[] dbBytes = null;

        try {
            fis = new FileInputStream(FILE_DIR.getPath() + "/" + this.dbName + ".db");
            fis.read(header);
            fis.read(hmac);
            dbBytes = new byte[fis.available()];
        } catch (FileNotFoundException e) {
            System.err.println("That password database does not exist. Exiting.");
            System.exit(1);
        } catch (IOException e) {
            e.printStackTrace();
        }

        System.out.println("Loading " + FILE_DIR.getPath() + "/" + this.dbName + ".db");
        System.out.print("Password: ");
        char[] password = this.cons.readPassword();

        km = new KeyManager(password, header);

        if (Crypto.verifyHmac(km.getHmacKey(), hmac, dbBytes)) {
            pd = new PasswordDatabase(Crypto.aesDecrypt(km.getAesKey(), km.getIV(), dbBytes));
            this.menu();
        } else {
            System.err.println("Error: Incorrect password or corrupt database. Exiting.");
            System.exit(1);
        }
    }

    public void keygen() {
        //TODO: password encrypt key
        System.out.print("Generating public/private RSA key pair.\n" +
            "Enter file in which to save the keys: ");
        String keyName = scan.nextLine();
        ObjectOutputStream pubOutput;
        ObjectOutputStream privOutput;

        if (km == null) {
            km = new KeyManager();
        }
        km.generateRSAKeys();

        try {
            pubOutput = new ObjectOutputStream(
            new FileOutputStream(KEY_DIR.getPath() + "/" + keyName + ".pub"));
            privOutput = new ObjectOutputStream(
            new FileOutputStream(KEY_DIR.getPath() + "/" + keyName + ".priv"));
            pubOutput.writeObject(km.getPublic());
            pubOutput.flush();
            pubOutput.close();
            privOutput.writeObject(km.getPrivate());
            privOutput.flush();
            privOutput.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        System.out.println("Public key written to '" + KEY_DIR.getPath() + "/" + keyName + ".pub'");
        System.out.println("Private key written to '" + KEY_DIR.getPath() + "/" + keyName + ".priv'\n");

        // go to menu
        this.menu();
    }

    private void menu() {
        boolean done = false;

        while(!done) {
            System.out.println("What would you like to do?\n" +
                "1. List entries\n" +
                "2. View an entry\n" +
                "3. Add a new entry\n" +
                "4. Modify an entry\n" +
                "5. Save and exit\n" +
                "6. Exit\n");
            System.out.print("Your choice (1-6): ");
            int choice = scan.nextInt();
            scan.nextLine(); // eat new line

            switch (choice) {
                case 1: this.listEntries(); break;
                case 2: this.getEntry(); break;
                case 3: this.addEntry(); break;
                case 4: this.modify(); break;
                case 5: this.save();
                case 6: this.exit(); break;
                default: System.out.println("Invalid choice.\n");
            }
        }
    }

    private void listEntries() {
        String[] aliases = pd.getAliases();

        if (aliases.length == 0) {
            System.out.println("There are currently no entries.\n");
        } else {
            int i = 0;
            for (String s : aliases) {
                System.out.println((i++) + ". " + s);
            }

            System.out.print("Enter entry number to view (0-" + (i-1)  + "): ");
            int choice = scan.nextInt();
            scan.nextLine();

            this.getEntry(aliases[choice]);
        }

        this.menu();
    }

    private void getEntry() {
        System.out.print("Enter alias of entry to view: ");
        String alias = scan.nextLine();
        this.getEntry(alias);
    }

    private void getEntry(String alias) {
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

    private void addEntry() {
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
        } catch (EntryDoesNotExistException e) {
            System.out.println("An entry for '" + alias + "' does not exist.\n");
        }
    }

    private void save() {
        byte[] header = km.getHeader();
        byte[] encryptedBytes = Crypto.aesEncrypt(km.getAesKey(), km.getIV(), pd.getBytes());
        byte[] hmac = Crypto.getHmac(km.getHmacKey(), encryptedBytes);

        FileOutputStream fos;
        try {
            fos = new FileOutputStream(FILE_DIR.getPath() + "/" + this.dbName + ".db");
            fos.write(header);
            fos.write(hmac);
            fos.write(encryptedBytes);
            fos.flush();
            fos.close();
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

        System.exit(0);
    }
}