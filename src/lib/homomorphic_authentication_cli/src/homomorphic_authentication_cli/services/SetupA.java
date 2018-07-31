package homomorphic_authentication_cli.services;

import homomorphic_authentication_library_Java.crypto.pairing.PairingAGenerator;
import homomorphic_authentication_library_Java.io.ElementConversionTool;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

public class SetupA extends
        Setup {

    private final int r;
    private final int q;



    public SetupA(int r, int q) {
        super();
        this.r = r;
        this.q = q;

        pG = new PairingAGenerator(r, q);
    }
}
