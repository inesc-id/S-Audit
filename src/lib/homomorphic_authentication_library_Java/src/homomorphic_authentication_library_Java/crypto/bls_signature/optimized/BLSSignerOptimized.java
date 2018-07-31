package homomorphic_authentication_library_Java.crypto.bls_signature.optimized;

import it.unisa.dia.gas.crypto.jpbc.signature.bls01.params.BLS01KeyParameters;
import it.unisa.dia.gas.crypto.jpbc.signature.bls01.params.BLS01PrivateKeyParameters;
import it.unisa.dia.gas.crypto.jpbc.signature.bls01.params.BLS01PublicKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.Point;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;

import homomorphic_authentication_library_Java.crypto.bls_signature.BLSSigner;



public class BLSSignerOptimized extends
        BLSSigner {


    public BLSSignerOptimized(Digest digest, Element w) {
        super();
        this.w = w;
        this.digest = digest;
        this.g = null;

        // Reset the digest
        digest.reset();
    }

    public BLSSignerOptimized(Digest digest, Element w, Element g) {
        super();
        this.w = w;
        this.digest = digest;
        this.g = g;

        // Reset the digest
        digest.reset();
    }

    public void init(boolean forSigning, CipherParameters param) {
        if (!(param instanceof BLS01KeyParameters))
            throw new IllegalArgumentException(
                    "Invalid parameters. Expected an instance of BLS01KeyParameters.");

        keyParameters = (BLS01KeyParameters) param;

        if (forSigning && !keyParameters.isPrivate())
            throw new IllegalArgumentException("signing requires private key");
        else if (forSigning) {
            this.key = ((BLS01PrivateKeyParameters) keyParameters).getSk();
        }
        if (!forSigning && keyParameters.isPrivate())
            throw new IllegalArgumentException("verification requires public key");
        else if (!forSigning) {
            this.key = ((BLS01PublicKeyParameters) keyParameters).getPk();
            this.g = ((BLS01PublicKeyParameters) keyParameters).getParameters().getG();
        }

        this.pairing = PairingFactory.getPairing(keyParameters.getParameters().getParameters());
    }

    public void init(Element key, Pairing pairing) {
        this.pairing = pairing;
        this.key = key;
    }

    public boolean verifySignature(byte[][] signature, byte[][] mk, String id, int num_splits) {
        if (key == null)
            throw new IllegalStateException("BLS engine not initialised");

        //BLS01PublicKeyParameters publicKey = (BLS01PublicKeyParameters) keyParameters;
        Element sig = pairing.getG1().newElement().setToOne();
        Element message = pairing.getZr().newElement().setToZero();
        Element idMul = pairing.getG1().newElement().setToOne();

        for (int i = 0; i < mk.length; i++) {
            String block_id = (id + "" + i);
            byte[] bytes_id = block_id.getBytes();

            // Generate the digest
            int digestSize = digest.getDigestSize();
            byte[] hash = new byte[digestSize];
            digest.reset();
            digest.update(bytes_id, 0, bytes_id.length);
            digest.doFinal(hash, 0);

            // Map the hash of the message m to some element of G1
            Element h_id = pairing.getG1().newElementFromHash(hash, 0, hash.length);
            idMul.mul(h_id);
            Element h_mk = pairing.getZr().newElementFromHash(mk[i], 0, mk[i].length);
            message = message.add(h_mk);
        }
        for (int i = 0; i < signature.length; i++) {
            Point sigP = (Point) pairing.getG1().newElement();
            int val = sigP.setFromBytesCompressed(signature[i]);
            sig.mul(sigP);
        }

        Element x = pairing.getG1().newElementFromBytes(w.toBytes());
        x.powZn(message);
        Element h = x.mul(idMul);

        Element temp1 = pairing.pairing(sig, g);
        Element temp2 = pairing.pairing(h, key);

        return temp1.isEqual(temp2);// || temp1.invert().isEqual(temp2);

        /* 
         if (!signer.verifySignature(signature[i], splitMessage[i], bytes_id)) {
             return false;
         }
        }*/
    }

    public boolean verifySignature(byte[] signature, byte[] mk, byte[] id) {
        if (key == null)
            throw new IllegalStateException("BLS engine not initialised");

        //BLS01PublicKeyParameters publicKey = (BLS01PublicKeyParameters) keyParameters;

        // Generate the digest
        int digestSize = digest.getDigestSize();
        byte[] hash = new byte[digestSize];
        digest.reset();
        digest.update(id, 0, id.length);
        digest.doFinal(hash, 0);

        // Map the hash of the message m to some element of G1
        Element h_id = pairing.getG1().newElementFromHash(hash, 0, hash.length);
        Element h_mk = pairing.getZr().newElementFromHash(mk, 0, mk.length);

        Element x = pairing.getG1().newElementFromBytes(w.toBytes());
        x.powZn(h_mk);
        Element h = x.mul(h_id);

        Point sig = (Point) pairing.getG1().newElement();
        sig.setFromBytesCompressed(signature);

        Element temp1 = pairing.pairing(sig, g);
        Element temp2 = pairing.pairing(h, key);

        return temp1.isEqual(temp2);// || temp1.invert().isEqual(temp2);
    }

    public byte[] generateSignature(byte[] mk, byte[] id)
            throws CryptoException, DataLengthException {
        if (key == null)
            throw new IllegalStateException("BLS engine not initialised");

        // Generate the digest
        int digestSize = digest.getDigestSize();
        byte[] hash = new byte[digestSize];
        digest.reset();
        digest.update(id, 0, id.length);
        digest.doFinal(hash, 0);

        // Map the hash of the message m to some element of G1
        Element h_id = pairing.getG1().newElementFromHash(hash, 0, hash.length);
        Element h_mk = pairing.getZr().newElementFromHash(mk, 0, mk.length);

        Element x = pairing.getG1().newElementFromBytes(w.toBytes());
        x.powZn(h_mk);
        Element h = x.mul(h_id);

        // Generate the signature

        Element sigE = h.powZn(key);
        Point sig = (Point) sigE;
        return sig.toBytesCompressed();
    }

}
