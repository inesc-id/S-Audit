package homomorphic_authentication_cli.cli;

import homomorphic_authentication_cli.services.KeyGenerator;

public class CLIKeyGeneration {

    public static void main(String[] args) {
        // TODO Auto-generated method stub
        String pairingPath = args[0];
        String gPath = args[1];
        String wPath = args[2];
        String privateKeyPath = args[3];
        String publicKeyPath = args[4];
        boolean optimized = Boolean.valueOf(args[5]);

        KeyGenerator s =
            new KeyGenerator(pairingPath, gPath, wPath, privateKeyPath, publicKeyPath, optimized);
        System.out.println(s.run());
    }

}
