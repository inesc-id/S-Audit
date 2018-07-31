package homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.challenge.input;

public class FileBlockChallenge {
    private int index;
    private int challenge_val;

    public FileBlockChallenge(int file_block_index, int challenge_value) {
        // TODO Auto-generated constructor stub
        this.index = file_block_index;
        this.challenge_val = challenge_value;
    }

    /**
     * @return the index
     */
    public int getIndex() {
        return index;
    }

    /**
     * @param index the index to set
     */
    public void setIndex(int index) {
        this.index = index;
    }

    /**
     * @return the challenge_val
     */
    public int getChallenge_val() {
        return challenge_val;
    }

    /**
     * @param challenge_val the challenge_val to set
     */
    public void setChallenge_val(int challenge_val) {
        this.challenge_val = challenge_val;
    }


}
