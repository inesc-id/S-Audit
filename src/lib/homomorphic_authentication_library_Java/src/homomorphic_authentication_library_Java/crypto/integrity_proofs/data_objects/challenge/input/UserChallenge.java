package homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.challenge.input;

import it.unisa.dia.gas.jpbc.Element;

import java.util.ArrayList;
import java.util.Collection;

public class UserChallenge {
    private Collection<FileChallenge> file_challenge_list = new ArrayList<>();
    private String id;
    private Element w;

    public UserChallenge(ArrayList<FileChallenge> file_challenge_list, String id, Element w) {
        this(id, w);
        this.file_challenge_list = file_challenge_list;
    }

    public UserChallenge(String id, Element w) {
        this(id);
        this.w = w;
    }

    public UserChallenge(String id) {
        super();
        this.id = id;
    }

    public void addFileChallenge(FileChallenge f_c) {
        file_challenge_list.add(f_c);
    }

    /**
     * @return the file_challenge_list
     */
    public Collection<FileChallenge> getFiles() {
        return file_challenge_list;
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
     * @param file_challenge_list the file_challenge_list to set
     */
    public void setFile_challenge_list(Collection<FileChallenge> file_challenge_list) {
        this.file_challenge_list = file_challenge_list;
    }

    /**
     * @return the file_challenge_list
     */
    public Collection<FileChallenge> getFile_challenge_list() {
        return file_challenge_list;
    }

    /**
     * @param id the id to set
     */
    public void setId(String id) {
        this.id = id;
    }

    /**
     * @param w the w to set
     */
    public void setW(Element w) {
        this.w = w;
    }


}
