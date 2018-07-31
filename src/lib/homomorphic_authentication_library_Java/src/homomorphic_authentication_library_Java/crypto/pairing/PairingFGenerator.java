package homomorphic_authentication_library_Java.crypto.pairing;

import homomorphic_authentication_library_Java.crypto.PairingFactory;
import homomorphic_authentication_library_Java.io.ElementConversionTool;
import it.unisa.dia.gas.crypto.jpbc.signature.bls01.params.BLS01Parameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.jpbc.PairingParametersGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.f.TypeFCurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pbc.curve.PBCTypeFCurveGenerator;




public class PairingFGenerator extends
        PairingGenerator {

    int rBits = 160;

    public PairingFGenerator(int rbits) {
        this.rBits = rbits;
    }

    public void generate() {
        TypeFCurveGenerator curveGenerator = new TypeFCurveGenerator(rBits);

        this.params = curveGenerator.generate();
        this.pairing = PairingFactory.getPairing(params);
        this.g = pairing.getG2().newRandomElement();
    }

    @Override
    public Element generateW() {
        return pairing.getG1().newRandomElement();
    }

    @Override
    public Element parseG(byte[] g) {
        return pairing.getG2().newElementFromBytes(g);
    }
}
