package homomorphic_authentication_library_Java.homo_hashing;

import java.util.Collection;

import homomorphic_authentication_library_Java.io.DataManipulator;
import homomorphic_authentication_library_Java.io.ElementConversionTool;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.GeneralDigest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.jce.provider.JCEMac.SHA1;

public class HomomorphicHasher extends
        GeneralDigest {
    private final Field f;
    private byte[] b;

    public HomomorphicHasher(Field f) {
        this.f = f;
        b = new byte[0];
    }

    @Override
    public int doFinal(byte[] arg0, int arg1) {
        update(arg0, 0, arg0.length);
        return 1;
    }

    public byte[] digest() {
        byte[][] ag = DataManipulator.split_message(b, f.getLengthInBytes());

        Element e = f.newElement().setToZero();
        for (int i = 0; i < ag.length; i++) {
            String s = "" + i;
            Element id = f.newElementFromHash(s.getBytes(), 0, s.length());
            Element mk = f.newElementFromHash(ag[i], 0, ag[i].length);

            id.mul(mk);
            e.add(id);
        }

        return e.toBytes();
    }


    @Override
    public String getAlgorithmName() {
        return "HomomorphicHasher";
    }

    @Override
    public int getDigestSize() {
        // TODO Auto-generated method stub
        return f.getLengthInBytes();
    }

    @Override
    public void reset() {
        // TODO Auto-generated method stub
        b = new byte[0];
    }

    @Override
    public void update(byte arg0) {
        // create a destination array that is the size of the two arrays
        byte[] destination = new byte[b.length + 1];

        // copy ciphertext into start of destination (from pos 0, copy ciphertext.length bytes)
        System.arraycopy(b, 0, destination, 0, b.length);

        // copy mac into end of destination (from pos ciphertext.length, copy mac.length bytes)
        System.arraycopy(arg0, 0, destination, b.length, 1);

        b = destination;
    }

    @Override
    public void update(byte[] arg0, int arg1, int arg2) {
        // create a destination array that is the size of the two arrays
        byte[] destination = new byte[b.length + arg0.length];

        // copy ciphertext into start of destination (from pos 0, copy ciphertext.length bytes)
        System.arraycopy(b, 0, destination, 0, b.length);

        // copy mac into end of destination (from pos ciphertext.length, copy mac.length bytes)
        System.arraycopy(arg0, 0, destination, b.length, arg0.length);

        b = destination;
    }

    @Override
    protected void processBlock() {
        // TODO Auto-generated method stub

    }

    @Override
    protected void processLength(long arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    protected void processWord(byte[] arg0, int arg1) {
        // TODO Auto-generated method stub

    }



}
