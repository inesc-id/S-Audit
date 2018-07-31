package homomorphic_authentication_cli.services;

import java.io.IOException;

import homomorphic_authentication_library_Java.crypto.bls_signature.BLS;
import homomorphic_authentication_library_Java.crypto.bls_signature.optimized.BLSOptimized;
import homomorphic_authentication_library_Java.crypto.pairing.PairingAGenerator;
import homomorphic_authentication_library_Java.crypto.pairing.PairingGenerator;
import homomorphic_authentication_library_Java.crypto.pairing.ParingGeneratorFactory;
import homomorphic_authentication_library_Java.io.DataManipulator;
import homomorphic_authentication_library_Java.io.ElementConversionTool;
import homomorphic_authentication_library_Java.io.FileSystemHandler;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;

public class TagVerifier extends
        HomomorphicAuthenticationService {



    private final String PAIRING_FILE_PATH;
    private final String G_FILE_PATH;
    private final String W_FILE_PATH;
    private final String PUBLIC_KEY_FILE_PATH;
    private final String FILE_ID;
    private final String FILE_PATH;
    private final String SIGNATURE_FILE_PATH;
    private boolean isOptimized;



    public TagVerifier(String pAIRING_FILE_PATH,
                       String g_FILE_PATH,
                       String w_FILE_PATH,
                       String pUBLIC_KEY_FILE_PATH,
                       String fILE_ID,
                       String fILE_PATH,
                       String sIGNATURE_FILE_PATH,
                       boolean isOptimized) {
        super();
        PAIRING_FILE_PATH = pAIRING_FILE_PATH;
        G_FILE_PATH = g_FILE_PATH;
        W_FILE_PATH = w_FILE_PATH;
        PUBLIC_KEY_FILE_PATH = pUBLIC_KEY_FILE_PATH;
        FILE_ID = fILE_ID;
        FILE_PATH = fILE_PATH;
        SIGNATURE_FILE_PATH = sIGNATURE_FILE_PATH;
        this.isOptimized = isOptimized;
    }

    @Override
    public String run() {
        String result = "";

        String params_s = FileSystemHandler.readFile(PAIRING_FILE_PATH);
        byte[] g_b;
        try {
            g_b = FileSystemHandler.readFileBytes(G_FILE_PATH);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        }

        PairingGenerator pG = ParingGeneratorFactory.getGenerator(params_s);
        pG.generate(params_s, g_b);
        PairingParameters pairingParameters = pG.getPairingParameters();
        Pairing pairing = pG.getPairing();
        Element g = pG.getG();

        byte[] w_b = null;
        byte[] pk_b = null;
        try {
            w_b = FileSystemHandler.readFileBytes(W_FILE_PATH);
            pk_b = FileSystemHandler.readFileBytes(PUBLIC_KEY_FILE_PATH);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        }
        Element w = ElementConversionTool.convertBytesToElement(w_b, pairing.getG1());

        Element pk = ElementConversionTool.convertBytesToElement(pk_b, pairing.getG2());

        byte[] sig_b;
        try {
            sig_b = FileSystemHandler.readFileBytes(SIGNATURE_FILE_PATH);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        }

        int splitSize;
        if (isOptimized) {
            splitSize = pairing.getG1().getLengthInBytes() / 2 + 1;
        } else {
            splitSize = pairing.getG1().getLengthInBytes();
        } //Client0
        byte[][] sig = DataManipulator.split_message(sig_b, splitSize);
        BLS bls;
        if (isOptimized) {
            bls = new BLSOptimized(pairingParameters, g, w);
        } else {
            bls = new BLS(pairingParameters, g, w);
        }
        String message = FileSystemHandler.readFile(FILE_PATH);
        String id = FILE_ID;

        if (bls.verify(sig, message, id, pk, pairing)) {
            result += ("integrity verifies!");
        } else {
            result += ("file has been tampered");
        }
        return result;
    }
}
