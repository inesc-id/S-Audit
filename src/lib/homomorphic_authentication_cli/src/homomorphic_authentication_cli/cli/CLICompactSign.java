package homomorphic_authentication_cli.cli;

import java.io.IOException;

import tagger.CompactStorageTagger;
import tagger.HashedStorageTagger;
import homomorphic_authentication_library_Java.io.FileSystemHandler;

public class CLICompactSign {

    public static void main(String[] args) {
        String pairingPath = args[0];
        String gPath = args[1];
        String wPath = args[2];
        String privateKeyPath = args[3];
        String publicKeyPath = args[4];

        String fILE_ID = args[5];
        String fILE_PATH = args[6];
        String sIGNATURE_OUT_FILE_PATH = args[7];
        double granularity = new Double(args[8]);

        HashedStorageTagger s;
        try {
            s = new HashedStorageTagger(FileSystemHandler.readFile(pairingPath),
                    FileSystemHandler.readFileBytes(gPath), FileSystemHandler.readFileBytes(wPath),
                    FileSystemHandler.readFileBytes(privateKeyPath), fILE_ID,
                    FileSystemHandler.readFileBytes(fILE_PATH), granularity);
            /* StorageTagger s = new StorageTagger(pairingPath, gPath, wPath, privateKeyPath, fILE_ID,
                 fILE_PATH, sIGNATURE_OUT_FILE_PATH);*/
            System.out.println(s.run());
            System.out.println("finished signature");
            System.out.println("writting file");
            FileSystemHandler.writeFile(sIGNATURE_OUT_FILE_PATH, s.getSignatureContent());
            System.out.println(">Success");
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

}
