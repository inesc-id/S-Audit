package homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.challenge.data;


import it.unisa.dia.gas.jpbc.Element;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;

public class UserAuditingObject {
    private final String id;
    private HashMap<String, FileAuditingObject> files;
    private Element w;

    public UserAuditingObject(String id) {
        this.id = id;
        files = new HashMap<>();

    }

    public UserAuditingObject(String id, Element w) {
        this(id);
        this.w = w;
    }

    public void addFile(String id, FileAuditingObject f) {
        files.put(id, f);
    }

    /**
     * @return the files
     */
    public Collection<FileAuditingObject> getFiles() {
        return files.values();
    }

    public FileAuditingObject getFile(String id) {
        return files.get(id);
    }

    /**
     * @return the id
     */
    public String getId() {
        return id;
    }

    /**
     * @return the w
     */
    public Element getW() {
        return w;
    }

    /**
     * @param files the files to set
     */
    public void setFiles(HashMap<String, FileAuditingObject> files) {
        this.files = files;
    }

    /**
     * @param w the w to set
     */
    public void setW(Element w) {
        this.w = w;
    }

}
