package tagger;



import org.bouncycastle.crypto.digests.SHA1Digest;

import homomorphic_authentication_library_Java.crypto.bls_signature.BLS;
import homomorphic_authentication_library_Java.crypto.pairing.PairingGenerator;
import homomorphic_authentication_library_Java.crypto.pairing.ParingGeneratorFactory;
import homomorphic_authentication_library_Java.homo_hashing.FileBlockHasher;
import homomorphic_authentication_library_Java.io.DataManipulator;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;

public class HashedStorageTagger extends
        HomomorphicAuthenticationService {
    private final Pairing pairing;
    private final Element g;
    private final Element w;
    private final Element sk;
    private final String FILE_ID;
    private final byte[] fileContent;
    private final int granularity;
    private final PairingParameters pairingParameters;
    private byte[][] signatureContent;
    private String signatureFileName;

    public HashedStorageTagger(String pairing_params,
                               byte[] g,
                               byte[] w,
                               byte[] sk,
                               String fILE_ID,
                               byte[] file,
                               int granularity) {
        super();


        PairingGenerator pG = ParingGeneratorFactory.getGenerator(pairing_params);
        pG.generate(pairing_params, g);
        pG.generate(pairing_params, g);
        this.pairingParameters = pG.getPairingParameters();
        this.pairing = pG.getPairing();
        this.g = pG.getG();

        //String w_s = FileSystemHandler.readFile(W_FILE_PATH);
        this.w = pairing.getG2().newElementFromBytes(w);
        this.sk = pairing.getZr().newElementFromBytes(sk);
        this.FILE_ID = fILE_ID;
        this.fileContent = file;
        this.granularity = granularity;
    }

    public HashedStorageTagger(String pairing_params,
                               byte[] g,
                               byte[] w,
                               byte[] sk,
                               String fILE_ID,
                               byte[] file,
                               double granularity) {


        PairingGenerator pG = ParingGeneratorFactory.getGenerator(pairing_params);
        pG.generate(pairing_params, g);
        pG.generate(pairing_params, g);
        this.pairingParameters = pG.getPairingParameters();
        pairing = pG.getPairing();
        this.g = pG.getG();

        //String w_s = FileSystemHandler.readFile(W_FILE_PATH);
        this.w = pairing.getG2().newElementFromBytes(w);
        this.sk = pairing.getZr().newElementFromBytes(sk);
        this.FILE_ID = fILE_ID;
        this.fileContent = file;

        this.granularity = FileBlockHasher.calculateGranularity(granularity, file.length,
                pairing.getZr().getLengthInBytes());
    }

    public HashedStorageTagger(PairingParameters pairingParameters,
                               Pairing pairing,
                               Element g,
                               Element w,
                               Element sk,
                               String fILE_ID,
                               byte[] file,
                               int granularity) {
        super();
        this.pairingParameters = pairingParameters;
        this.pairing = pairing;
        this.g = g;
        this.w = w;
        this.sk = sk;
        this.FILE_ID = fILE_ID;
        this.fileContent = file;
        this.granularity = granularity;
    }

    public HashedStorageTagger(PairingParameters pairingParameters,
                               Pairing pairing,
                               Element g,
                               Element w,
                               Element sk,
                               String fILE_ID,
                               byte[] file,
                               double granularity) {
        super();
        this.pairingParameters = pairingParameters;
        this.pairing = pairing;
        this.g = g;
        this.w = w;
        this.sk = sk;
        this.FILE_ID = fILE_ID;
        this.fileContent = file;
        this.granularity = FileBlockHasher.calculateGranularity(granularity, file.length,
                pairing.getZr().getLengthInBytes());
    }

    public String run() {
        String result = "";

        byte[] hash_file = FileBlockHasher.hashFileBlocks(fileContent, granularity,
                pairing.getZr().getLengthInBytes(), new SHA1Digest());

        //Client0
        BLS bls = new BLS(pairingParameters, g, w);
        byte[][] sig = bls.sign(hash_file, FILE_ID, sk);

        this.signatureContent = sig;
        this.signatureFileName = FILE_ID + ".sig";

        return result;
    }

    /**
     * @return the signatureContent
     */
    public byte[] getSignatureContent() {
        return DataManipulator.aggregateDataBlocks(pairing.getG1().getLengthInBytes(),
                signatureContent);

    }

    /**
     * @return the signatureFileName
     */
    public String getSignatureFileName() {
        return signatureFileName;
    }


}
