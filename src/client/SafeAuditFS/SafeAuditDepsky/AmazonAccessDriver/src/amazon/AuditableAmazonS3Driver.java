package amazon;

import tagger.StorageTagger;
import exceptions.StorageCloudException;

public class AuditableAmazonS3Driver extends
        AmazonS3Driver {

    private final String pairing_params;
    private final byte[] g;
    private final byte[] w;
    private final byte[] sk;
    private final boolean optimized;

    public AuditableAmazonS3Driver(String driverId,
                                   String accessKey,
                                   String secretKey,
                                   String pairing_params,
                                   byte[] g,
                                   byte[] w,
                                   byte[] sk,
                                   boolean optimized) {
        super(driverId, accessKey, secretKey);
        this.pairing_params = pairing_params;
        this.g = g;
        this.w = w;
        this.sk = sk;
        this.optimized = optimized;
    }

    @Override
    public String uploadData(String bucketName, byte[] data, String fileId, String[] canonicalIDs)
            throws StorageCloudException {
        String fileID = super.uploadData(bucketName, data, fileId, canonicalIDs);

        //sign with storage tagger
        StorageTagger t = new StorageTagger(pairing_params, g, w, sk, fileID, data, optimized);
        t.run();
        byte[] signature = t.getSignatureContent();

        //upload signature
        super.uploadData(bucketName, signature, t.getSignatureFileName(), canonicalIDs);

        return fileID;
    }



}
