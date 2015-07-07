public class EntryAlreadyExistsException extends Exception {
    public EntryAlreadyExistsException() {
        super("An entry with the same alias already exists in the database.");
    }
}
