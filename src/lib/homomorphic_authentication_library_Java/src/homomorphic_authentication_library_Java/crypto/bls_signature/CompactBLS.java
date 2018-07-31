package homomorphic_authentication_library_Java.crypto.bls_signature;

import homomorphic_authentication_library_Java.crypto.PairingFactory;
import homomorphic_authentication_library_Java.io.DataManipulator;
import homomorphic_authentication_library_Java.io.ElementConversionTool;
import it.unisa.dia.gas.crypto.jpbc.signature.bls01.generators.BLS01KeyPairGenerator;
import it.unisa.dia.gas.crypto.jpbc.signature.bls01.params.BLS01KeyGenerationParameters;
import it.unisa.dia.gas.crypto.jpbc.signature.bls01.params.BLS01Parameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.digests.SHA256Digest;


/**
 * @author Angelo De Caro (jpbclib@gmail.com)
 */
public class CompactBLS {
    private Element w;
    private CompactBLSSigner signer;
    private BLS01Parameters parameters;
    private Pairing pairing;
    private Element g;
    int granularity;

    public CompactBLS(PairingParameters params, Element g, Element w, int granularity) {
        this.w = w;
        this.parameters = new BLS01Parameters(params, g);
        this.g = g;
        this.pairing = PairingFactory.getPairing(params);
        this.granularity = granularity;
    }

    public AsymmetricCipherKeyPair keyGen() {
        BLS01KeyPairGenerator keyGen = new BLS01KeyPairGenerator();
        keyGen.init(new BLS01KeyGenerationParameters(null, parameters));

        AsymmetricCipherKeyPair kp = keyGen.generateKeyPair();

        return kp;
    }


    private byte[] sign_block(byte[] message, byte[] id, CompactBLSSigner signer) {
        byte[] signature = null;

        try {
            signature = signer.generateSignature(message, id);
        } catch (CryptoException e) {
            throw new RuntimeException(e);
        }
        return signature;
    }

    public byte[][] sign(String message, String id, CipherParameters privateKey) throws DataLengthException,
            CryptoException {
        return this.sign(message.getBytes(), id, privateKey);
    }

    public byte[][] sign(byte[] message, String id, CipherParameters privateKey) throws DataLengthException,
            CryptoException {
        int keyLength = pairing.getZr().getLengthInBytes();
        byte[][] splitMessage = DataManipulator.split_message(message, keyLength);

        int num_splits = splitMessage.length;
        byte[][] signature = new byte[num_splits][];
        signer = new CompactBLSSigner(new SHA256Digest(), w, granularity);
        signer.init(true, privateKey);

        for (int i = 0; i < num_splits; i++) {
            String block_id = (id + "" + i);
            byte[] bytes_id = block_id.getBytes();
            signature[i] = sign_block(splitMessage[i], bytes_id, signer);
        }

        signature = compactSignature(signature, id);


        return signature;
    }

    private byte[][] compactSignature(byte[][] signature, String id) throws DataLengthException,
            CryptoException {
        boolean hasRemaining = true;
        int numChunks = signature.length / granularity;
        int remainingChunk = signature.length % granularity;
        if (remainingChunk > 0) {
            numChunks++;
        }
        byte[][] newGranSig = new byte[numChunks][signature[0].length];

        for (int i = 0; i < numChunks - 1; i++) {
            Element newSigBlock = pairing.getG1().newElement().setToOne();
            for (int z = 0; z < granularity; z++) {
                Element block = ElementConversionTool.convertBytesToElement(signature[i
                        * granularity + z], pairing.getG1());
                newSigBlock.mul(block);
            }
            newGranSig[i] = newSigBlock.toBytes();
        }

        Element newSigBlock = pairing.getG1().newElement().setToOne();
        int z;
        for (z = 0; (z < granularity && remainingChunk == 0) || z < remainingChunk; z++) {
            Element block = ElementConversionTool.convertBytesToElement(signature[(numChunks - 1)
                    * granularity + z], pairing.getG1());
            newSigBlock.mul(block);
        }
        //fill with padding
        for (; (z < granularity && remainingChunk > 0); z++) {
            int index = (numChunks - 1) * granularity + z;
            byte[] padding = signer.generateNullSignature((id + index).getBytes());
            Element block = ElementConversionTool.convertBytesToElement(padding, pairing.getG1());
            newSigBlock.mul(block);
        }
        newGranSig[(numChunks - 1)] = newSigBlock.toBytes();

        signature = newGranSig;
        return signature;
    }

    public byte[][] sign(String message, String id, Element key) throws DataLengthException,
            CryptoException {
        return sign(message.getBytes(), id, key);
    }

    public byte[][] sign(byte[] message, String id, Element key) throws DataLengthException,
            CryptoException {
        int keyLength = pairing.getZr().getLengthInBytes();
        byte[][] splitMessage = DataManipulator.split_message(message, keyLength);

        int num_splits = splitMessage.length;
        byte[][] signature = new byte[num_splits][];
        signer = new CompactBLSSigner(new SHA256Digest(), w, granularity);
        signer.init(key, pairing);

        for (int i = 0; i < num_splits; i++) {
            String block_id = (id + "" + i);
            byte[] bytes_id = block_id.getBytes();
            signature[i] = sign_block(splitMessage[i], bytes_id, signer);
        }


        signature = compactSignature(signature, id);

        return signature;
    }

    public boolean verify(byte[] signature, String message, String id, CipherParameters publicKey) {
        byte[] bytes_mk = message.getBytes();
        byte[] bytes_id = id.getBytes();

        CompactBLSSigner signer = new CompactBLSSigner(new SHA256Digest(), w, granularity);
        signer.init(false, publicKey);

        return signer.verifySignature(signature, bytes_mk, bytes_id);
    }

    public boolean verify(byte[][] signature, String message, String id, CipherParameters publicKey) {
        return this.verify(signature, message.getBytes(), id, publicKey);
    }

    public boolean verify(byte[][] signature, byte[] message, String id, CipherParameters publicKey) {

        CompactBLSSigner signer = new CompactBLSSigner(new SHA256Digest(), w, granularity);
        signer.init(false, publicKey);

        int keyLength = pairing.getZr().getLengthInBytes();
        byte[][] splitMessage = DataManipulator.split_message(message, keyLength);

        //int num_splits = splitMessage.length;

        /*if (signature.length != splitMessage.length) {
            return false;
        }*/

        if (!signer.verifySignature(signature, splitMessage, id)) {
            return false;
        }
        return true;
    }

    public boolean verify(byte[] signature,
                          String message,
                          String id,
                          Element publicKey,
                          Pairing pairing) {

        byte[] bytes_mk = message.getBytes();
        byte[] bytes_id = id.getBytes();

        BLSSigner signer = new BLSSigner(new SHA256Digest(), w, g);
        signer.init(publicKey, pairing);

        return signer.verifySignature(signature, bytes_mk, bytes_id);
    }

    public boolean verify(byte[][] signature,
                          String message,
                          String id,
                          Element publicKey,
                          Pairing pairing) {
        BLSSigner signer = new BLSSigner(new SHA256Digest(), w, g);
        signer.init(publicKey, pairing);

        int keyLength = pairing.getZr().getLengthInBytes();
        byte[][] splitMessage = DataManipulator.split_message(message, keyLength);

        int num_splits = splitMessage.length;
        if (signature.length != splitMessage.length) {
            return false;
        }
        for (int i = 0; i < num_splits; i++) {
            String block_id = (id + "" + i);
            byte[] bytes_id = block_id.getBytes();

            if (!signer.verifySignature(signature[i], splitMessage[i], bytes_id)) {
                return false;
            }
        }
        return true;
    }

    public boolean verify_block(byte[][] signature,
                                String message,
                                String id,
                                Element publicKey,
                                Pairing pairing,
                                int block_index) {
        BLSSigner signer = new BLSSigner(new SHA256Digest(), w, g);
        signer.init(publicKey, pairing);

        int keyLength = pairing.getZr().getLengthInBytes();
        byte[] message_block = DataManipulator
                .get_block(message.getBytes(), keyLength, block_index);

        String block_id = (id + "" + block_index);
        byte[] bytes_id = block_id.getBytes();

        if (!signer.verifySignature(signature[block_index], message_block, bytes_id)) {
            return false;
        }

        return true;
    }

    /**
     * @return the w
     */
    public Element getW() {
        return w;
    }
}
