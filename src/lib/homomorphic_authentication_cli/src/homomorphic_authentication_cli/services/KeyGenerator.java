package homomorphic_authentication_cli.services;

import java.io.IOException;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

import homomorphic_authentication_library_Java.crypto.bls_signature.BLS;
import homomorphic_authentication_library_Java.crypto.bls_signature.optimized.BLSOptimized;
import homomorphic_authentication_library_Java.crypto.pairing.PairingAGenerator;
import homomorphic_authentication_library_Java.crypto.pairing.PairingGenerator;
import homomorphic_authentication_library_Java.crypto.pairing.ParingGeneratorFactory;
import homomorphic_authentication_library_Java.io.ElementConversionTool;
import homomorphic_authentication_library_Java.io.FileSystemHandler;
import it.unisa.dia.gas.crypto.jpbc.signature.bls01.params.BLS01PrivateKeyParameters;
import it.unisa.dia.gas.crypto.jpbc.signature.bls01.params.BLS01PublicKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;

public class KeyGenerator extends
        HomomorphicAuthenticationService {
    private final String pairingFilePath;
    private final String gFilePath;
    private final String wOutputFilePath;
    private final String privateKeyOutputFilePath;
    private final String publicKeyOutputFilePath;
    private boolean isOptimized;



    public KeyGenerator(String pAIRING_FILE_PATH,
                        String g_FILE_PATH,
                        String w_OUT_FILE_PATH,
                        String privateKeyOutputFilePath,
                        String publicKeyOutputFilePath,
                        boolean optimized) {
        super();
        this.pairingFilePath = pAIRING_FILE_PATH;
        this.gFilePath = g_FILE_PATH;
        this.wOutputFilePath = w_OUT_FILE_PATH;
        this.privateKeyOutputFilePath = privateKeyOutputFilePath;
        this.publicKeyOutputFilePath = publicKeyOutputFilePath;
        this.isOptimized = optimized;
    }

    public String run() {
        String result = "";
        if (pairingFilePath == null || gFilePath == null || wOutputFilePath == null
                || privateKeyOutputFilePath == null || publicKeyOutputFilePath == null
                || pairingFilePath.isEmpty() || gFilePath.isEmpty() || wOutputFilePath.isEmpty()
                || privateKeyOutputFilePath.isEmpty() || publicKeyOutputFilePath.isEmpty())
            throw new RuntimeException("error: please fill all text boxes");
        String params_s = FileSystemHandler.readFile(pairingFilePath);
        byte[] g_b;
        try {
            g_b = FileSystemHandler.readFileBytes(gFilePath);
        } catch (IOException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
            return null;
        }

        PairingGenerator pG = ParingGeneratorFactory.getGenerator(params_s);
        pG.generate(params_s, g_b);
        PairingParameters pairingParameters = pG.getPairingParameters();
        Pairing pairing = pG.getPairing();
        Element g = pG.getG();

        Element w = pG.generateW();
        try {
            FileSystemHandler.writeFile(wOutputFilePath, w.toBytes());
        } catch (IOException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
            return null;
        }
        BLS bls0 = null;
        if (isOptimized) {
            bls0 = new BLSOptimized(pairingParameters, g, w);
        } else {
            bls0 = new BLS(pairingParameters, g, w);
        }
        AsymmetricCipherKeyPair keyPair0 = bls0.keyGen();

        Element sk = ((BLS01PrivateKeyParameters) keyPair0.getPrivate()).getSk();
        Element pk = ((BLS01PublicKeyParameters) keyPair0.getPublic()).getPk();
        try {
            FileSystemHandler.writeFile(privateKeyOutputFilePath, sk.toBytes());
            FileSystemHandler.writeFile(publicKeyOutputFilePath, pk.toBytes());
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        result += "g: " + ElementConversionTool.convertElementToString(g) + '\n';
        result += "sk: " + ElementConversionTool.convertElementToString(sk) + '\n';
        result += "pk: " + ElementConversionTool.convertElementToString(pk) + '\n';
        result += "w: " + ElementConversionTool.convertElementToString(w) + '\n';

        return result;
    }
}
