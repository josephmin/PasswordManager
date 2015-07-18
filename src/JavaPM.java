import java.io.Console;
import java.io.File;
import java.util.Arrays;
import java.util.Scanner;

public class JavaPM {
    private static final File KEY_DIR = new File("keys");
    private static final File FILE_DIR = new File("files");

    private Scanner scan;
    private Console cons;
    private KeyManager km;
    private String dbName;


    public static void main(String[] args) {
        JavaPM pm = new JavaPM();
        if (args.length != 0) {
            switch (args[0]) {
                case "init": pm.init();
                case "keygen": pm.keygen();
            }
        }
    }

    private JavaPM() {
        scan = new Scanner(System.in);
        cons = System.console();
    }

    private void init() {
        System.out.print("Name of database: ");
        dbName = scan.next();
        scan.nextLine();
        char[] password = this.createPassword();
        this.km = new KeyManager(password);
        KEY_DIR.mkdir();
        FILE_DIR.mkdir();

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

    private void keygen() {
        //TODO: password encrypt key
        System.out.print("Generating public/private RSA key pair.\n" +
            "Enter file in which to save the keys (" + KEY_DIR.getPath() + "/): ");
        String keyName = scan.next();
        scan.nextLine();
        FileOutputStream fos = new FileOutputStream(KEY_DIR.getName() + "/" + )

    }

    private void menu() {
        System.out.println("What would you like to do?\n" +
            "1. List entries\n" +
            "2. View an entry\n" +
            "3. Add a new entry\n");
        System.out.print("Your choice (1-3): ");
        scan.next();
        scan.nextLine();
    }
}