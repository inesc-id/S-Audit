package homomorphic_authentication_cli.services;

import org.bouncycastle.crypto.digests.SHA1Digest;

import homomorphic_authentication_library_Java.crypto.bls_signature.BLS;
import homomorphic_authentication_library_Java.crypto.pairing.PairingAGenerator;
import homomorphic_authentication_library_Java.homo_hashing.FileBlockHasher;
import homomorphic_authentication_library_Java.io.DataManipulator;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;

public class HashedTagVerifier extends
        HomomorphicAuthenticationService {

    private final Pairing pairing;
    private final Element g;
    private final Element w;
    private final Element pk;
    private final String FILE_ID;
    private final byte[] fileContent;
    private final byte[] signatureContent;
    private final String signatureFileName;
    private final int granularity;
    private final PairingParameters pairingParameters;

    public HashedTagVerifier(String pairing_params,
                             byte[] g,
                             byte[] w,
                             byte[] pk,
                             String fILE_ID,
                             byte[] file,
                             int granularity,
                             String sig_ID,
                             byte[] sig) {
        super();

        PairingAGenerator pG = new PairingAGenerator();
        pG.generate(pairing_params, g);
        this.pairingParameters = pG.getPairingParameters();
        this.pairing = pG.getPairing();
        this.g = pG.getG();

        //String w_s = FileSystemHandler.readFile(W_FILE_PATH);
        this.w = pairing.getG2().newElementFromBytes(w);
        this.pk = pairing.getG2().newElementFromBytes(pk);
        this.FILE_ID = fILE_ID;
        this.fileContent = file;
        this.granularity = granularity;

        this.signatureFileName = sig_ID;
        this.signatureContent = sig;
    }

    public HashedTagVerifier(String pairing_params,
                             byte[] g,
                             byte[] w,
                             byte[] pk,
                             String fILE_ID,
                             byte[] file,
                             double granularity,
                             String sig_ID,
                             byte[] sig) {
        super();

        PairingAGenerator pG = new PairingAGenerator();
        pG.generate(pairing_params, g);
        this.pairingParameters = pG.getPairingParameters();
        this.pairing = pG.getPairing();
        this.g = pG.getG();

        //String w_s = FileSystemHandler.readFile(W_FILE_PATH);
        this.w = pairing.getG2().newElementFromBytes(w);
        this.pk = pairing.getG2().newElementFromBytes(pk);
        this.FILE_ID = fILE_ID;
        this.fileContent = file;
        this.granularity = FileBlockHasher.calculateGranularity(granularity, file.length,
                pairing.getZr().getLengthInBytes());

        this.signatureFileName = sig_ID;
        this.signatureContent = sig;
    }

    public HashedTagVerifier(PairingParameters pairingParameters,
                             Pairing pairing,
                             Element g,
                             Element w,
                             Element pk,
                             String fILE_ID,
                             byte[] file,
                             int granularity,
                             String sig_ID,
                             byte[] sig) {
        super();

        this.pairingParameters = pairingParameters;
        this.pairing = pairing;
        this.g = g;
        this.w = w;
        this.pk = pk;
        this.FILE_ID = fILE_ID;
        this.fileContent = file;
        this.granularity = granularity;
        this.signatureFileName = sig_ID;
        this.signatureContent = sig;
    }

    public HashedTagVerifier(PairingParameters pairingParameters,
                             Pairing pairing,
                             Element g,
                             Element w,
                             Element pk,
                             String fILE_ID,
                             byte[] file,
                             double granularity,
                             String sig_ID,
                             byte[] sig) {
        super();

        this.pairingParameters = pairingParameters;
        this.pairing = pairing;
        this.g = g;
        this.w = w;
        this.pk = pk;
        this.FILE_ID = fILE_ID;
        this.fileContent = file;
        this.signatureFileName = sig_ID;
        this.signatureContent = sig;
        this.granularity = FileBlockHasher.calculateGranularity(granularity, file.length,
                pairing.getZr().getLengthInBytes());
    }

    @Override
    public String run() {

        String result = "";

        byte[] hash_file = FileBlockHasher.hashFileBlocks(fileContent, granularity,
                pairing.getZr().getLengthInBytes(), new SHA1Digest());

        //Client0
        BLS bls = new BLS(pairingParameters, g, w);

        byte[][] sig_b =
            DataManipulator.split_message(signatureContent, pairing.getG1().getLengthInBytes());
        //Client0

        if (bls.verify(sig_b, hash_file, FILE_ID, pk, pairing)) {
            result += ("integrity verifies!");
        } else {
            result += ("file has been tampered");
        }
        return result;
    }
}
