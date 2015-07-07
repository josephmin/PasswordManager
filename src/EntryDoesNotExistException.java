public class EntryDoesNotExistException extends Exception {
    public EntryDoesNotExistException() {
        super("Entry does not exist in the database.");
    }
}
