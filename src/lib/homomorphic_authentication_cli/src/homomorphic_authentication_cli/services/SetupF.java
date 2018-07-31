package homomorphic_authentication_cli.services;

import homomorphic_authentication_library_Java.crypto.pairing.PairingFGenerator;
import it.unisa.dia.gas.jpbc.Element;

public class SetupF extends
        Setup {

    private final int r;
    //private final String PAIRING_FILE_OUT_PATH;
    //private final String G_FILE_OUT_PATH;

    private String pairingParameters = null;
    private Element g = null;



    public SetupF(int r/*, String pAIRING_FILE_OUT_PATH, String g_FILE_OUT_PATH*/) {
        super();
        this.r = r;
        /*this.PAIRING_FILE_OUT_PATH = pAIRING_FILE_OUT_PATH;
        this.G_FILE_OUT_PATH = g_FILE_OUT_PATH;*/
        pG = new PairingFGenerator(r);
    }
}
