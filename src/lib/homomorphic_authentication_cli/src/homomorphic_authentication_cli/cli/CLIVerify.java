package homomorphic_authentication_cli.cli;

import homomorphic_authentication_cli.services.TagVerifier;

public class CLIVerify {

    public static void main(String[] args) {
        String pairingPath = args[0];
        String gPath = args[1];
        String wPath = args[2];
        String publicKeyPath = args[3];
        String fILE_ID = args[4];
        String fILE_PATH = args[5];
        String sIGNATURE_OUT_FILE_PATH = args[6];
        boolean optimized = Boolean.valueOf(args[7]);

        TagVerifier s = new TagVerifier(pairingPath, gPath, wPath, publicKeyPath, fILE_ID,
                fILE_PATH, sIGNATURE_OUT_FILE_PATH, optimized);
        System.out.println(s.run());
    }

}
