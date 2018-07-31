package homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.challenge.input;

import java.util.Collection;
import java.util.HashMap;

public class Challenge {
    private final HashMap<String, UserChallenge> user_challenge_set;

    @SuppressWarnings("unchecked")
    public Challenge(HashMap<String, UserChallenge> user_challenge_set) {
        super();
        this.user_challenge_set = (HashMap<String, UserChallenge>) user_challenge_set.clone();
    }

    public Challenge() {
        super();
        this.user_challenge_set = new HashMap<String, UserChallenge>();
    }

    public void addUserChallenge(String id, UserChallenge u_c) {
        this.user_challenge_set.put(id, u_c);
    }

    /**
     * @return the user_challenge_set
     */
    public UserChallenge getUser_challenge_set(String user_id) {
        return user_challenge_set.get(user_id);
    }

    public Collection<UserChallenge> getUser_challenge_set() {
        return user_challenge_set.values();
    }
}
