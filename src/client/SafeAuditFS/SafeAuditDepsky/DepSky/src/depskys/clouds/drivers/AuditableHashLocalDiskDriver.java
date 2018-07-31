package depskys.clouds.drivers;

import exceptions.StorageCloudException;
import homomorphic_authentication_library_Java.crypto.pairing.PairingGenerator;
import homomorphic_authentication_library_Java.crypto.pairing.ParingGeneratorFactory;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import tagger.HashedStorageTagger;

public class AuditableHashLocalDiskDriver extends
        LocalDiskDriver {

    private final PairingParameters pairingParameters;
    private final Pairing pairing;
    private final Element g;
    private final Element w;
    private final Element sk;
    private double granularity;

    public AuditableHashLocalDiskDriver(String driverpath,
                                        String ip,
                                        String pairing_params,
                                        byte[] g,
                                        byte[] w,
                                        byte[] sk,
                                        double granularity) {
        this(driverpath, ip, 5555, pairing_params, g, w, sk, granularity);
    }

    public AuditableHashLocalDiskDriver(String driverpath,
                                        String ip,
                                        int port,
                                        String pairing_params,
                                        byte[] g,
                                        byte[] w,
                                        byte[] sk,
                                        double granularity) {
        super(driverpath, ip, port);
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

        System.out.println("Writing signature: " + t.getSignatureFileName());
        //upload signature
        super.uploadData(bucketName, signature, t.getSignatureFileName(), canonicalIDs);

        return fileID;
    }

}
