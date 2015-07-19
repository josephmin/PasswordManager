import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Set;

public class PasswordDatabase implements Serializable {
    private static final long serialVersionUID = 1L; //default
    private static final float LOAD_FACTOR = 0.75f;
    private static final int INIT_CAPACITY = 16;

    private HashMap<String, String[]> hm;

    public PasswordDatabase() {
        hm = new HashMap<String, String[]>(INIT_CAPACITY, LOAD_FACTOR);
    }

    @SuppressWarnings("unchecked")
    public PasswordDatabase(byte[] b) {
        ByteArrayInputStream bais;
        ObjectInputStream ois;
        try {
            bais = new ByteArrayInputStream(b);
            ois = new ObjectInputStream(bais);
            Object o = ois.readObject();
            if (o instanceof HashMap) {
                hm = (HashMap<String, String[]>) o;
            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    public void addEntry(String alias, String[] entry)
            throws EntryAlreadyExistsException, InvalidEntryException {
        if (hm.containsKey(alias)) {
            throw new EntryAlreadyExistsException();
        } else {
            if (entry.length == 3) {
                hm.put(alias, entry);
            } else {
                throw new InvalidEntryException();
            }
        }
    }

    public void removeEntry(String alias) throws EntryDoesNotExistException {
        if (hm.containsKey(alias)) {
            hm.remove(alias);
        } else {
            throw new EntryDoesNotExistException();
        }
    }

    public String[] getEntry(String alias) throws EntryDoesNotExistException {
        String[] entry;
        if (hm.containsKey(alias)) {
            entry = hm.get(alias);
        } else {
            throw new EntryDoesNotExistException();
        }
        return entry;
    }

    public void modifyEntry(String alias, String[] newEntry) throws EntryDoesNotExistException {
        if (hm.containsKey(alias)) {
            hm.replace(alias, newEntry);
        } else {
            throw new EntryDoesNotExistException();
        }
    }

    public String[] getAliases() {
        Set<String> set = hm.keySet();
        return set.toArray(new String[set.size()]);
    }

    public byte[] getBytes() {
        byte[] b = null;
        ByteArrayOutputStream baos;
        ObjectOutputStream oos;
        try {
            baos = new ByteArrayOutputStream();
            oos = new ObjectOutputStream(baos);
            oos.writeObject(hm);
            oos.flush();
            oos.close();
            b = baos.toByteArray();
            baos.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return b;
    }
}