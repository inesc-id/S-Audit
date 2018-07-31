package homomorphic_authentication_cli.services;

import homomorphic_authentication_library_Java.crypto.pairing.PairingGenerator;
import homomorphic_authentication_library_Java.io.ElementConversionTool;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

public abstract class Setup extends
        HomomorphicAuthenticationService {

    protected String pairingParameters = null;
    protected Element g = null;
    protected PairingGenerator pG;

    public String run() {
        ///////////////
        // Setup
        ///////////////
        String result = "";

        pG.generate();

        PairingParameters p = pG.getPairingParameters();
        result += "PARAMS:" + '\n';
        result += p.toString() + '\n';

        pairingParameters = p.toString();
        //

        g = pG.getG();
        result += "G:" + '\n';
        result += ElementConversionTool.convertElementToString(g) + '\n';

        return result;
    }

    /**
     * @return the pairingParameters
     */
    public String getPairingParameters() {
        return pairingParameters;
    }

    /**
     * @return the g
     */
    public Element getG() {
        return g;
    }
}
