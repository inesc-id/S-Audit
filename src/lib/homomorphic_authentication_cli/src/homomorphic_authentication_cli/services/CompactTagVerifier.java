package homomorphic_authentication_cli.services;

import java.io.IOException;

import homomorphic_authentication_library_Java.crypto.bls_signature.BLS;
import homomorphic_authentication_library_Java.io.DataManipulator;
import homomorphic_authentication_library_Java.io.ElementConversionTool;
import homomorphic_authentication_library_Java.io.FileSystemHandler;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;

public class CompactTagVerifier extends
        TagVerifier {
    int granularity;

    public CompactTagVerifier(String pAIRING_FILE_PATH,
                              String g_FILE_PATH,
                              String w_FILE_PATH,
                              String pUBLIC_KEY_FILE_PATH,
                              String fILE_ID,
                              String fILE_PATH,
                              String sIGNATURE_FILE_PATH,
                              int granulatiry) {
        super(pAIRING_FILE_PATH, g_FILE_PATH, w_FILE_PATH, pUBLIC_KEY_FILE_PATH, fILE_ID, fILE_PATH,
                sIGNATURE_FILE_PATH, false);
        this.granularity = granulatiry;

    }

    @Override
    public String run() {
        /*PairingAGenerator pG = new PairingAGenerator(true);
        pG.generate(params_s, g_b);
        PairingParameters pairingParameters = pG.getPairingParameters();
        Pairing pairing = pG.getPairing();
        
        byte[][] alpha = DataManipulator.split_message(message, pairing.getZr().getLengthInBytes());
        
        boolean hasRemaining = true;
        int numChunks = alpha.length / granularity;
        int remainingChunk = alpha.length % granularity;
        if (remainingChunk > 0) {
            numChunks++;
        }
        byte[][] newGranSig = new byte[numChunks][alpha[0].length];
        
        for (int i = 0; i < numChunks - 1; i++) {
            Element newSigBlock = pairing.getZr().newElement().setToOne();
            for (int z = 0; z < granularity; z++) {
                Element block = ElementConversionTool.convertBytesToElement(alpha[i * granularity
                        + z], pairing.getZr());
                newSigBlock.add(block);
            }
            newGranSig[i] = newSigBlock.toBytes();
        }
        
        Element newSigBlock = pairing.getG1().newElement().setToOne();
        for (int z = 0; (z < granularity && remainingChunk == 0) || z < remainingChunk; z++) {
            Element block = ElementConversionTool.convertBytesToElement(alpha[(numChunks - 1)
                    * granularity + z], pairing.getG1());
            newSigBlock.add(block);
        }
        newGranSig[(numChunks - 1)] = newSigBlock.toBytes();
        
        alpha = newGranSig;
        
        
        
        
        
        
        
        String result = super.run();
        return result;*/ return null;
    }
}
