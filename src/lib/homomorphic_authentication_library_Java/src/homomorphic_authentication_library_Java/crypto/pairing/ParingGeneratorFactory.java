package homomorphic_authentication_library_Java.crypto.pairing;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import homomorphic_authentication_library_Java.crypto.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;

public class ParingGeneratorFactory {

    //use getShape method to get object of type shape 
    public static PairingGenerator getGenerator(String params) {
        PropertiesParameters p = new PropertiesParameters();
        p.load(new ByteArrayInputStream(params.getBytes(StandardCharsets.UTF_8)));

        String curveType = p.getType();
        if (curveType == null) {
            return null;
        }
        if (curveType.equalsIgnoreCase("a")) {
            return new PairingAGenerator();

        } else if (curveType.equalsIgnoreCase("f")) {
            return new PairingFGenerator(0);
        }

        return null;
    }
}
