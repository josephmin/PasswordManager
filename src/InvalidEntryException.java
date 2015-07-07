public class InvalidEntryException extends Exception {
    private static final long serialVersionUID = 1L; //default

    public InvalidEntryException() {
        super("Entry must have username, password, and comment.");
    }
}
