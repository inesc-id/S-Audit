package tagger;

import homomorphic_authentication_library_Java.crypto.bls_signature.BLS;
import homomorphic_authentication_library_Java.crypto.bls_signature.optimized.BLSOptimized;
import homomorphic_authentication_library_Java.crypto.pairing.PairingGenerator;
import homomorphic_authentication_library_Java.crypto.pairing.ParingGeneratorFactory;
import homomorphic_authentication_library_Java.io.DataManipulator;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;

public class StorageTagger extends
        HomomorphicAuthenticationService {

    private final Pairing pairing;
    private final Element g;
    private final Element w;
    private final Element sk;
    private final String FILE_ID;
    private final byte[] fileContent;
    private final PairingParameters pairingParameters;
    private byte[][] signatureContent;
    private String signatureFileName;
    private boolean isOptimized;

    public StorageTagger(String pairing_params,
                         byte[] g,
                         byte[] w,
                         byte[] sk,
                         String fILE_ID,
                         byte[] file,
                         boolean isOptimized) {
        super();

        PairingGenerator pG = ParingGeneratorFactory.getGenerator(pairing_params);
        pG.generate(pairing_params, g);
        this.pairingParameters = pG.getPairingParameters();
        this.pairing = pG.getPairing();
        this.g = pG.getG();

        //String w_s = FileSystemHandler.readFile(W_FILE_PATH);
        this.w = pairing.getG1().newElementFromBytes(w);
        this.sk = pairing.getZr().newElementFromBytes(sk);
        this.FILE_ID = fILE_ID;
        this.fileContent = file;
        this.isOptimized = isOptimized;
    }

    public StorageTagger(PairingParameters pairingParameters,
                         Pairing pairing,
                         Element g,
                         Element w,
                         Element sk,
                         String fILE_ID,
                         byte[] file,
                         boolean isOptimized) {
        super();
        this.pairingParameters = pairingParameters;
        this.pairing = pairing;
        this.g = g;
        this.w = w;
        this.sk = sk;
        this.FILE_ID = fILE_ID;
        this.fileContent = file;
        this.isOptimized = isOptimized;
    }

    public String run() {
        String result = "";

        //Client0
        BLS bls;

        if (isOptimized) {
            bls = new BLSOptimized(pairingParameters, g, w);
        } else {
            bls = new BLS(pairingParameters, g, w);
        }
        byte[][] sig = bls.sign(fileContent, FILE_ID, sk);

        this.signatureContent = sig;
        this.signatureFileName = FILE_ID + ".sig";

        return result;
    }

    /**
     * @return the signatureContent
     */
    public byte[] getSignatureContent() {
        int splitSize;
        if (isOptimized) {
            splitSize = pairing.getG1().getLengthInBytes() / 2 + 1;
        } else {
            splitSize = pairing.getG1().getLengthInBytes();
        }
        return DataManipulator.aggregateDataBlocks(splitSize, signatureContent);

    }

    /**
     * @return the signatureFileName
     */
    public String getSignatureFileName() {
        return signatureFileName;
    }


}
