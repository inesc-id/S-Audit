package storage_integrity_verifier.json;

import it.unisa.dia.gas.jpbc.Element;

public class UserAuthenticationMetadata {
    final String username;
    final String pub_key;
    final String w;



    public UserAuthenticationMetadata(String username, String pk, String w) {
        super();
        this.username = username;
        this.pub_key = pk;
        this.w = w;
    }

    /**
     * @return the username
     */
    public String getUsername() {
        return username;
    }

    /**
     * @return the pub_key
     */
    public String getPub_key() {
        return pub_key;
    }

    /**
     * @return the w
     */
    public String getW() {
        return w;
    }


}
