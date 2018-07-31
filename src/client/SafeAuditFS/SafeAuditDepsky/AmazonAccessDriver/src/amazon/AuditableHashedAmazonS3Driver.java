package amazon;

import exceptions.StorageCloudException;
import homomorphic_authentication_library_Java.crypto.pairing.PairingGenerator;
import homomorphic_authentication_library_Java.crypto.pairing.ParingGeneratorFactory;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import tagger.HashedStorageTagger;

public class AuditableHashedAmazonS3Driver extends
        AmazonS3Driver {

    private final PairingParameters pairingParameters;
    private final Pairing pairing;
    private final Element g;
    private final Element w;
    private final Element sk;
    private double granularity;

    public AuditableHashedAmazonS3Driver(String driverId,
                                         String accessKey,
                                         String secretKey,
                                         String pairing_params,
                                         byte[] g,
                                         byte[] w,
                                         byte[] sk,
                                         double granularity) {
        super(driverId, accessKey, secretKey);
        PairingGenerator pG = ParingGeneratorFactory.getGenerator(pairing_params);
        pG.generate(pairing_params, g);
        this.pairingParameters = pG.getPairingParameters();
        this.pairing = pG.getPairing();
        this.g = pG.getG();

        //String w_s = FileSystemHandler.readFile(W_FILE_PATH);
        this.w = pairing.getG2().newElementFromBytes(w);
        this.sk = pairing.getG2().newElementFromBytes(sk);
        this.granularity = granularity;
    }

    @Override
    public String uploadData(String bucketName, byte[] data, String fileId, String[] canonicalIDs)
            throws StorageCloudException {
        String fileID = super.uploadData(bucketName, data, fileId, canonicalIDs);

        //sign with storage tagger
        HashedStorageTagger t = new HashedStorageTagger(pairingParameters, pairing, g, w, sk,
                fileID, data, granularity);
        t.run();
        byte[] signature = t.getSignatureContent();

        //upload signature
        super.uploadData(bucketName, signature, t.getSignatureFileName(), canonicalIDs);

        return fileID;
    }



}
