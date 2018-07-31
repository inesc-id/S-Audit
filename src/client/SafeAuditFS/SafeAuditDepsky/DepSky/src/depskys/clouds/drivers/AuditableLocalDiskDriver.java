package depskys.clouds.drivers;

import exceptions.StorageCloudException;
import homomorphic_authentication_library_Java.crypto.pairing.PairingGenerator;
import homomorphic_authentication_library_Java.crypto.pairing.ParingGeneratorFactory;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import tagger.StorageTagger;

public class AuditableLocalDiskDriver extends
        LocalDiskDriver {

    private final PairingParameters pairingParameters;
    private final Pairing pairing;
    private final Element g;
    private final Element w;
    private final Element sk;
    private final boolean isOptimized;

    public AuditableLocalDiskDriver(String driverpath,
                                    String ip,
                                    String pairing_params,
                                    byte[] g,
                                    byte[] w,
                                    byte[] sk,
                                    boolean isOptimized) {
        this(driverpath, ip, 5555, pairing_params, g, w, sk, isOptimized);
    }

    public AuditableLocalDiskDriver(String driverpath,
                                    String ip,
                                    int port,
                                    String pairing_params,
                                    byte[] g,
                                    byte[] w,
                                    byte[] sk,
                                    boolean isOptimized) {
        super(driverpath, ip, port);
        PairingGenerator pG = ParingGeneratorFactory.getGenerator(pairing_params);
        pG.generate(pairing_params, g);
        this.pairingParameters = pG.getPairingParameters();
        this.pairing = pG.getPairing();
        this.g = pG.getG();

        //String w_s = FileSystemHandler.readFile(W_FILE_PATH);
        this.w = pairing.getG2().newElementFromBytes(w);
        this.sk = pairing.getG2().newElementFromBytes(sk);

        this.isOptimized = isOptimized;
    }

    @Override
    public String uploadData(String bucketName, byte[] data, String fileId, String[] canonicalIDs)
            throws StorageCloudException {
        String fileID = super.uploadData(bucketName, data, fileId, canonicalIDs);
        //sign with storage tagger
        StorageTagger t =
            new StorageTagger(pairingParameters, pairing, g, w, sk, fileID, data, isOptimized);
        t.run();
        byte[] signature = t.getSignatureContent();

        System.out.println("Writing signature: " + t.getSignatureFileName());
        //upload signature
        super.uploadData(bucketName, signature, t.getSignatureFileName(), canonicalIDs);

        return fileID;
    }

}
