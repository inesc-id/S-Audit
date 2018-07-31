package json;

import homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.challenge.data.FileAuditingObject;

public class S3FileAuditingObject extends
        FileAuditingObject {
    private String bucketName;

    public S3FileAuditingObject(String bucket, String fileId, int fileSize, int blockSize) {
        super(fileId, fileSize, blockSize);
        this.bucketName = bucket;
    }

    /**
     * @return the bucketName
     */
    public String getBucketName() {
        return bucketName;
    }

    /**
     * @param bucketName the bucketName to set
     */
    public void setBucketName(String bucketName) {
        this.bucketName = bucketName;
    }



}
