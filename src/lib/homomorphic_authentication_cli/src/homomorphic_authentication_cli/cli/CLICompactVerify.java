package homomorphic_authentication_cli.cli;

import java.io.IOException;

import tagger.HashedStorageTagger;
import homomorphic_authentication_cli.services.HashedTagVerifier;
import homomorphic_authentication_cli.services.TagVerifier;
import homomorphic_authentication_library_Java.io.FileSystemHandler;

public class CLICompactVerify {

    public static void main(String[] args) {
        String pairingPath = args[0];
        String gPath = args[1];
        String wPath = args[2];
        String privateKeyPath = args[3];
        String publicKeyPath = args[4];
        String fILE_ID = args[5];
        String fILE_PATH = args[6];
        String SIG_PATH = args[7];
        double granularity = new Double(args[8]);
        HashedTagVerifier s;
        try {
            s = new HashedTagVerifier(FileSystemHandler.readFile(pairingPath),
                    FileSystemHandler.readFileBytes(gPath), FileSystemHandler.readFileBytes(wPath),
                    FileSystemHandler.readFileBytes(publicKeyPath), fILE_ID,
                    FileSystemHandler.readFileBytes(fILE_PATH), granularity, fILE_ID + ".sig",
                    FileSystemHandler.readFileBytes(SIG_PATH));
        } catch (IOException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
            return;
        }

        System.out.println(s.run());
    }

}
