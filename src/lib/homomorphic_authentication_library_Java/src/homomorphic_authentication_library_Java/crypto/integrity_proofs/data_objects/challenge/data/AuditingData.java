package homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.challenge.data;

import java.util.Collection;
import java.util.HashMap;

public class AuditingData {
    private HashMap<String, UserAuditingObject> users;

    public AuditingData() {
        this(new HashMap<String, UserAuditingObject>());
    }

    public AuditingData(HashMap<String, UserAuditingObject> users) {
        super();
        this.users = users;
    }

    /**
     * @return the users
     */
    public Collection<UserAuditingObject> getUsers() {
        return users.values();
    }

    /**
     * @param users the users to set
     */
    public void setUsers(HashMap<String, UserAuditingObject> users) {
        this.users = users;
    }

    public UserAuditingObject getUser(String id) {
        return this.users.get(id);
    }

    public void addUser(String id, UserAuditingObject u) {
        this.users.put(id, u);
    }

}
