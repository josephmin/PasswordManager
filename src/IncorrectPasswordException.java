public class IncorrectPasswordException extends Exception{

    private static final long serialVersionUID = 1L;

    public IncorrectPasswordException() {
        super("Incorrect Password");
    }

}
