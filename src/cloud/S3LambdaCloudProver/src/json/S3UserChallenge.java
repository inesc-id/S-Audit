package json;

import homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.challenge.input.FileChallenge;
import homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.challenge.input.UserChallenge;

import it.unisa.dia.gas.jpbc.Element;

import java.util.ArrayList;

public class S3UserChallenge extends
        UserChallenge {
    String bucket_name;

    public S3UserChallenge(String id, String bucket_name) {
        super(id);
        this.bucket_name = bucket_name;
    }

    public S3UserChallenge(String id, Element w, String bucket_name) {
        super(id, w);
        this.bucket_name = bucket_name;
    }

    public S3UserChallenge(ArrayList<FileChallenge> file_challenge_list,
                           String id,
                           Element w,
                           String bucket_name) {
        super(file_challenge_list, id, w);
        this.bucket_name = bucket_name;
    }

    /**
     * @return the bucket_name
     */
    public String getBucket_name() {
        return bucket_name;
    }

    /**
     * @param bucket_name the bucket_name to set
     */
    public void setBucket_name(String bucket_name) {
        this.bucket_name = bucket_name;
    }


}
