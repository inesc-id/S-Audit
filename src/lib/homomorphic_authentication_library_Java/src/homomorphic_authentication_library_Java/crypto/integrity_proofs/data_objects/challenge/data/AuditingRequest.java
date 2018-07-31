package homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.challenge.data;

import homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.challenge.input.Challenge;

public class AuditingRequest {
    private Challenge challenge;
    private AuditingData data;

    public AuditingRequest(Challenge challenge, AuditingData data) {
        super();
        this.challenge = challenge;
        this.data = data;
    }

    /**
     * @return the challenge
     */
    public Challenge getChallenge() {
        return challenge;
    }

    /**
     * @param challenge the challenge to set
     */
    public void setChallenge(Challenge challenge) {
        this.challenge = challenge;
    }

    /**
     * @return the data
     */
    public AuditingData getData() {
        return data;
    }

    /**
     * @param data the data to set
     */
    public void setData(AuditingData data) {
        this.data = data;
    }


}
