package homomorphic_authentication_library_Java.crypto.pairing;

import homomorphic_authentication_library_Java.crypto.PairingFactory;
import homomorphic_authentication_library_Java.io.ElementConversionTool;
import it.unisa.dia.gas.crypto.jpbc.signature.bls01.params.BLS01Parameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

public class PairingAGenerator extends
        PairingGenerator {

    // For secure signatures use 1024 bit keys: r=160bits and q=512-bit 
    private int r_size_bits;
    private int q_size_bits;

    public PairingAGenerator() {
        r_size_bits = 160;
        q_size_bits = 512;
    }

    public PairingAGenerator(int r_size_bits, int q_size_bits) {
        super();
        this.r_size_bits = r_size_bits;
        this.q_size_bits = q_size_bits;
    }

    public void generate() {
        TypeACurveGenerator curveGenerator = new TypeACurveGenerator(r_size_bits, q_size_bits);
        this.params = curveGenerator.generate();
        this.pairing = PairingFactory.getPairing(params);
        this.g = pairing.getG2().newRandomElement();
    }

    public Element generateW() {
        return pairing.getG2().newRandomElement();
    }

    @Override
    public Element parseG(byte[] g) {
        return pairing.getG2().newElementFromBytes(g);
    }
}
