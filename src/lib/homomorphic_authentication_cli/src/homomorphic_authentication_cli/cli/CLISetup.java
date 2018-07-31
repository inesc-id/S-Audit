package homomorphic_authentication_cli.cli;

import homomorphic_authentication_cli.services.Setup;
import homomorphic_authentication_cli.services.SetupA;
import homomorphic_authentication_cli.services.SetupF;
import homomorphic_authentication_library_Java.io.FileSystemHandler;
import it.unisa.dia.gas.jpbc.Element;

import java.io.IOException;


public class CLISetup {

    public static void main(String[] args) {
        String pairingPath = args[0];
        String gPath = args[1];
        String curveType = args[2].toLowerCase();

        Setup setup;
        if (curveType.equals("a")) {
            int r = Integer.parseInt(args[3]);
            int q = Integer.parseInt(args[4]);
            setup = new SetupA(r, q);
        } else if (curveType.equals("f")) {
            int r = Integer.parseInt(args[3]);
            setup = new SetupF(r);
        } else {
            throw new UnsupportedOperationException("No curve for the type specified");
        }

        setup.run();

        String pairing = setup.getPairingParameters();
        Element g = setup.getG();

        try {
            FileSystemHandler.writeFile(gPath, g.toBytes());
            FileSystemHandler.writeFile(pairingPath, pairing);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return;
        }
    }

}
