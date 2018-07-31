package homomorphic_authentication_library_Java.crypto.pairing;

import homomorphic_authentication_library_Java.crypto.PairingFactory;
import homomorphic_authentication_library_Java.io.ElementConversionTool;
import it.unisa.dia.gas.crypto.jpbc.signature.bls01.params.BLS01Parameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

public abstract class PairingGenerator {

    protected PairingParameters params = null;
    protected Pairing pairing = null;
    protected Element g = null;
    protected Element w = null;

    public abstract void generate();

    public void generate(PairingParameters params, Element g) {
        this.params = params;
        this.pairing = PairingFactory.getPairing(params);
        this.g = g.getImmutable();
    }

    public void generate(String params, byte[] g) {
        this.params = PairingFactory.getPairingParameters(params);
        this.pairing = PairingFactory.getPairing(params);
        this.g = parseG(g);
    }

    public void generate(String params, Element g) {
        this.params = PairingFactory.getPairingParameters(params);
        this.pairing = PairingFactory.getPairing(params);
        this.g = g;
    }

    public abstract Element generateW();

    public PairingParameters parsePairingParameters(String params) {
        return PairingFactory.getPairingParameters(params);
    }

    /**
     * @return the params
     */
    public PairingParameters getPairingParameters() {
        return params;
    }

    /**
     * @return the pairing
     */
    public Pairing getPairing() {
        return pairing;
    }

    /**
     * @return the g
     */
    public Element getG() {
        return g;
    }

    public abstract Element parseG(byte[] g);



}
