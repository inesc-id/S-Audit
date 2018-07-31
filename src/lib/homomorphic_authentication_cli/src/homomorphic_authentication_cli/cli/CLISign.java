package homomorphic_authentication_cli.cli;

import java.io.IOException;

import homomorphic_authentication_library_Java.io.FileSystemHandler;
import tagger.StorageTagger;


public class CLISign {

    public static void main(String[] args) {
        String pairingPath = args[0];
        String gPath = args[1];
        String wPath = args[2];
        String privateKeyPath = args[3];
        String publicKeyPath = args[4];

        String fILE_ID = args[5];
        String fILE_PATH = args[6];
        String sIGNATURE_OUT_FILE_PATH = args[7];
        boolean optimized = Boolean.valueOf(args[8]);
        StorageTagger s;
        try {
            s = new StorageTagger(FileSystemHandler.readFile(pairingPath),
                    FileSystemHandler.readFileBytes(gPath), FileSystemHandler.readFileBytes(wPath),
                    FileSystemHandler.readFileBytes(privateKeyPath), fILE_ID,
                    FileSystemHandler.readFileBytes(fILE_PATH), optimized);
            System.out.println(s.run());
            FileSystemHandler.writeFile(sIGNATURE_OUT_FILE_PATH, s.getSignatureContent());
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return;
        }
    }

}
