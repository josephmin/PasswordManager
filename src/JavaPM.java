public class JavaPM {
    public static void main(String[] args) {
        PasswordManager pm = new PasswordManager();
        if (args.length == 1) {
            switch (args[0]) {
                case "help": PasswordManager.help(); break;
                case "init": pm.init(); break;
                case "keygen": pm.keygen(); break;
                case "load": pm.load();break;
                case "sign": pm.sign(); break;
                case "verify": pm.verify(); break;
                default: System.out.println("Invalid argument.");
            }
        } else {
            System.err.println("JavaPM takes only a single argument. Use 'help' to see available arguments.\n");
            System.exit(1);
        }
    }
}