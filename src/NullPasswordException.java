public class NullPasswordException extends Exception {
    public NullPasswordException() {
        super("Password cannot be null.");
    }
}