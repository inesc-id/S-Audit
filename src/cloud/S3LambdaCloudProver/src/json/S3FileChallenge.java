package json;

import java.util.Collection;

import homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.challenge.input.FileBlockChallenge;
import homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.challenge.input.FileChallenge;

public class S3FileChallenge extends
        FileChallenge {
    private String bucket;

    public S3FileChallenge(String id, String bucket) {
        super(id);
        this.bucket = bucket;
        // TODO Auto-generated constructor stub
    }


    public S3FileChallenge(String id, String bucket, Collection<FileBlockChallenge> file_blocks) {
        super(id, file_blocks);
        this.bucket = bucket;
        // TODO Auto-generated constructor stub
    }

    public S3FileChallenge(String id, String bucket, int globalChallenge) {
        super(id, globalChallenge);
        this.bucket = bucket;
        // TODO Auto-generated constructor stub
    }


    public S3FileChallenge(String id,
                           String bucket,
                           Collection<FileBlockChallenge> file_blocks,
                           int globalChallenge) {
        super(id, file_blocks, globalChallenge);
        this.bucket = bucket;
        // TODO Auto-generated constructor stub
    }
}
