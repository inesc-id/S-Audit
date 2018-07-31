package homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.proof;

public class Proof {
    final byte[] alpha;
    final byte[] beta;
    String user;

    public Proof(byte[] alpha, byte[] beta, String user) {
        super();
        this.alpha = alpha;
        this.beta = beta;
        this.user = user;
    }

    /**
     * @return the alpha
     */
    public byte[] getAlpha() {
        return alpha;
    }

    /**
     * @return the beta
     */
    public byte[] getBeta() {
        return beta;
    }

    /**
     * @return the user
     */
    public String getUser() {
        return user;
    }

    /**
     * @param user the user to set
     */
    public void setUser(String user) {
        this.user = user;
    }
}
