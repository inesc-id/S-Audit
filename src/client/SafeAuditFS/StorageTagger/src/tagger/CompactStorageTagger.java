package tagger;

import it.unisa.dia.gas.jpbc.Element;
import homomorphic_authentication_library_Java.io.ElementConversionTool;

public class CompactStorageTagger extends
        StorageTagger {
    private final int granularity;

    public CompactStorageTagger(String pairing_params,
                                byte[] g,
                                byte[] w,
                                byte[] sk,
                                String fILE_ID,
                                byte[] file,
                                int granulatity) {
        super(pairing_params, g, w, sk, fILE_ID, file, false);
        this.granularity = granulatity;
    }

    /* (non-Javadoc)
     * @see tagger.StorageTagger#run()
     */
    @Override
    public String run() {
        /*   // TODO Auto-generated method stub
        String s = super.run();
        
        boolean hasRemaining = true;
        int numChunks = signatureContent.length / granularity;
        int remainingChunk = signatureContent.length % granularity;
        if (remainingChunk > 0) {
            numChunks++;
        }
        byte[][] newGranSig = new byte[numChunks][signatureContent[0].length];
        
        for (int i = 0; i < numChunks - 1; i++) {
            Element newSigBlock = pairing.getG1().newElement().setToOne();
            for (int z = 0; z < granularity; z++) {
                Element block = ElementConversionTool.convertBytesToElement(signatureContent[i
                        * granularity + z], pairing.getG1());
                newSigBlock.mul(block);
            }
            newGranSig[i] = newSigBlock.toBytes();
        }
        
        Element newSigBlock = pairing.getG1().newElement().setToOne();
        for (int z = 0; (z < granularity && remainingChunk == 0) || z < remainingChunk; z++) {
            Element block = ElementConversionTool.convertBytesToElement(
                    signatureContent[(numChunks - 1) * granularity + z], pairing.getG1());
            newSigBlock.mul(block);
        }
        newGranSig[(numChunks - 1)] = newSigBlock.toBytes();
        
        signatureContent = newGranSig;
        return s;*/
        return null;
    }
}
