import java.io.Console;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.Arrays;
import java.util.Scanner;

public class JavaPM {
    private Scanner scan;
    private Console cons;
    private String username;
    private char[] password;
    private KeyManager km;
    private File databaseFile;
    private PasswordDatabase pd;
    private String[] aliases;

    public JavaPM() {
        this.scan = new Scanner(System.in);
        this.cons = System.console();
        this.username = null;
        this.password = null;
        this.databaseFile = null;
    }

    public static void main(String[] args) {
        JavaPM pm = new JavaPM();
        Scanner scan = new Scanner(System.in);
        if (args.length != 0) {
            if (args[0].equals("init")) {
                pm.init();
                System.out.println("Please login with your new account.\n");
            } else {
                System.err.println("Invalid argument.\n"
                        + "Please use 'init' to create a new account.");
                System.exit(1);
            }
        }

        System.out.println("Welcome to JavaPM.");
        pm.login();
        pm.load();
        pm.menu();
    }

    private void init() {
        System.out.print("Please enter a username: ");
        String username = scan.nextLine();
        char[] password = this.createPassword();
        KeyManager km = new KeyManager(username, password);
        String overwrite = "y";
        if (km.exists()) {
            boolean valid = false;
            System.out.println("Keys for '" + username + "' already exists.");
            while (!valid) {
                System.out.print("Would you like to overwrite existing keys? (y/n) ");
                overwrite = scan.nextLine();
                if (overwrite.equalsIgnoreCase("y") || overwrite.equalsIgnoreCase("n")) {
                    valid = true;
                } else {
                    System.out.println("Invalid entry. Please try again.\n");
                }
            }
        }
        if (overwrite.equalsIgnoreCase("y")) {
            km.generateKeys();
        }
    }

    private char[] createPassword() {
        boolean valid = false;
        char[] passwd = null;
        while (!valid) {
            while (passwd == null || passwd.length == 0) {
                passwd = cons.readPassword("%s", "Please enter a password: ");
                if (passwd.length == 0) {
                    System.err.println("Password cannot be null.");
                }
            }
            if (Arrays.equals(passwd, cons.readPassword("%s", "Confirm password: "))) {
                valid = true;
            } else {
                System.err.println("Passwords do not match.\n"
                    + "Please try again.\n");
                passwd = null;
            }
        }
        return passwd;
    }

    private void login() {
        System.out.print("Username: ");
        this.username = scan.nextLine();
        this.password = cons.readPassword("%s", "Password: ");
        this.km = new KeyManager(this.username, this.password);
        try {
            this.km.readPublicKey();
            this.km.readPrivateKey();
        } catch (IncorrectPasswordException e) {
            System.out.println("The password you entered is not correct.\n");
            this.login();
        } catch (FileNotFoundException e) {
            System.out.println("Keys for '" + this.username + "' do not exist.\n"
                    + "Please use 'init' to create a new account.\n");
            System.exit(0);
        }
        this.databaseFile = new File("files/" + username + ".db");
    }

    private void load() {
        if (this.databaseFile.exists()) {
            FileInputStream fis;
            byte[] encryptedDB = null;
            try {
                fis = new FileInputStream(this.databaseFile);
                encryptedDB = new byte[fis.available()];
                fis.read(encryptedDB);
                fis.close();
            } catch (IOException e) {
                e.printStackTrace();
                System.exit(1);
            }

            if (encryptedDB != null) {
                Crypto c = new Crypto(this.password);
                byte[] encodedDB = c.unencryptBytes(encryptedDB);
                this.pd = new PasswordDatabase(encodedDB);
            }
        } else {
            File fileDir = new File("files");
            fileDir.mkdir();
            this.pd = new PasswordDatabase();
        }
    }

    private void menu() {
        int choice;
        while (true) {
            System.out.println("\nWhat would you like to do?");
            System.out.println("1. List entries\n"
                    + "2. View an entry\n"
                    + "3. Add a new entry\n"
                    + "4. Modify an entry\n"
                    + "5. Delete an entry\n"
                    + "6. Save and exit\n"
                    + "7. Exit");
            System.out.print("Your choice: ");
            choice = scan.nextInt();
            scan.nextLine(); //eat new line
            switch (choice) {
            case 1: this.listEntries(); break;
            case 2: this.getEntry(); break;
            case 3: this.addEntry(); break;
            case 4: this.modifyEntry(); break;
            case 6: this.save();
            case 7: this.exit(); break;
            default: System.out.println("Invalid entry.\n");
            }
            System.out.print("Press Enter to continue...");
            scan.nextLine();
        }
    }

    private void listEntries() {
        aliases = pd.getAliases();
        if (aliases.length == 0) {
            System.out.println("There are currently no entries.\n");
        } else {
            for (String s : aliases) {
                System.out.println("* " + s);
            }
            System.out.println();
        }
    }

    private void getEntry() {
        String[] entry = null;
        String alias;
        System.out.print("Alias to view: ");
        alias = scan.nextLine();
        try {
            entry = pd.getEntry(alias);
        } catch (EntryDoesNotExistException e) {
            System.out.println("That entry does not exist.\n");
        }
        if (entry != null) {
            System.out.println("Username: " + entry[0]);
            System.out.println("Password: " + entry[1]);
            System.out.println("Comment: " + entry[2] + "\n");
        }
    }

    private void addEntry() {
        String[] entry = new String[3];
        String alias;
        System.out.print("Alias: ");
        alias = scan.nextLine();
        System.out.print("Username: ");
        entry[0] = scan.nextLine();
        entry[1] = new String(cons.readPassword("%s", "Password: "));
        System.out.print("Comment: ");
        entry[2] = scan.nextLine();
        try {
            pd.addEntry(alias, entry);
        } catch (EntryAlreadyExistsException e) {
            System.out.println("An entry with the same alias already exists.");
        } catch (InvalidEntryException e) {
            e.printStackTrace();
        }
    }

    private void modifyEntry() {
        String alias;
        String[] oldEntry = null;
        String[] newEntry = new String[3];
        System.out.println("Alias to modify: ");
        alias = scan.nextLine();
        oldEntry = pd.getEntry(alias);
        System.out.println("Username (" + oldEntry[0] + "): ");
        newEntry[0] = scan.nextLine();
        System.out.println("Password (" + oldEntry[1] + "): ");
        newEntry[1] = new String(cons.readPassword());
        System.out.println("Comment: (" + oldEntry[2] + "): ");
        newEntry[2] = scan.nextLine();

        pd.replaceEntry(alias, newEntry);
    }

    private void save() {
        byte[] pdBytes = pd.getBytes();
        Crypto c = new Crypto(this.password);
        byte[] encrypted = c.encryptBytes(pdBytes);

        FileOutputStream fos;
        try {
            fos = new FileOutputStream(this.databaseFile);
            fos.write(encrypted);
            fos.flush();
            fos.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println("Saved to " + databaseFile.getPath());
    }

    private void exit() {
        System.out.println("Goodbye.\n");
        scan.close();
        System.exit(0);
    }


}
