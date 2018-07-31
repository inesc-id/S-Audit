package storage_integrity_verifier.service;

import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;

import org.bouncycastle.crypto.digests.SHA256Digest;

import com.amazonaws.util.json.JSONException;
import com.amazonaws.util.json.JSONObject;

import homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.challenge.input.Challenge;
import homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.challenge.input.UserChallenge;
import homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.proof.Proof;
import homomorphic_authentication_library_Java.crypto.integrity_proofs.proof_verifier.ProofVerifier;
import homomorphic_authentication_library_Java.crypto.pairing.PairingGenerator;
import homomorphic_authentication_library_Java.crypto.pairing.ParingGeneratorFactory;
import homomorphic_authentication_library_Java.io.ElementConversionTool;
import homomorphic_authentication_library_Java.io.FileSystemHandler;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import storage_integrity_verifier.json.ProofJSONConvertor;
import storage_integrity_verifier.json.RequestParser;
import storage_integrity_verifier.json.UserAuthenticationMetadata;

public class StorageIntegrityVerificationService extends
        HomomorphicAuthenticationService {


    final String PAIRING_FILE_PATH;
    final String G_FILE_PATH;
    final String W_FILE_PATH;
    final String PUBLIC_KEY_FILE_PATH;
    final String chal_s;
    final String proof_s;
    HashMap<String, UserAuthenticationMetadata> pub_keys_map = null;

    public StorageIntegrityVerificationService(String pAIRING_FILE_PATH,
                                               String g_FILE_PATH,
                                               String w_FILE_PATH,
                                               String pUBLIC_KEY_MAP,
                                               String chal,
                                               String proof) {
        super();
        PAIRING_FILE_PATH = pAIRING_FILE_PATH;
        G_FILE_PATH = g_FILE_PATH;
        W_FILE_PATH = w_FILE_PATH;
        PUBLIC_KEY_FILE_PATH = pUBLIC_KEY_MAP;
        chal_s = chal;
        proof_s = proof;
    }

    public String run() {
        String result = "";

        String params_s = FileSystemHandler.readFile(PAIRING_FILE_PATH);
        byte[] g_s;
        try {
            g_s = FileSystemHandler.readFileBytes(G_FILE_PATH);
        } catch (IOException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
            return null;
        }

        PairingGenerator pG = ParingGeneratorFactory.getGenerator(params_s);
        pG.generate(params_s, g_s);
        Pairing pairing = pG.getPairing();
        Element g = pG.getG();


        Collection<Proof> proofs = null;
        try {
            JSONObject json_proof = new JSONObject(proof_s);
            proofs = ProofJSONConvertor.jSONToProof(json_proof);
        } catch (JSONException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }


        RequestParser rP = new RequestParser();
        HashMap<String, UserAuthenticationMetadata> pub_keys_map = null;
        Challenge c = null;
        try {
            pub_keys_map =
                rP.convertInputToUserAuthenticationMetadata(new JSONObject(PUBLIC_KEY_FILE_PATH));
            c = rP.convertInputToChallenge(new JSONObject(chal_s));
        } catch (JSONException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        }

        HashMap<String, Element> user_pub_key_map = new HashMap<>();
        for (UserChallenge u : c.getUser_challenge_set()) {
            UserAuthenticationMetadata m = pub_keys_map.get(u.getId());
            byte[] w_s;
            try {
                w_s = FileSystemHandler.readFileBytes(m.getW());
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
                return null;
            }
            Element w = ElementConversionTool.convertBytesToElement(w_s, pairing.getG2());

            byte[] pk_s;
            try {
                pk_s = FileSystemHandler.readFileBytes(m.getPub_key());
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
                return null;
            }
            Element pk = ElementConversionTool.convertBytesToElement(pk_s, pairing.getG2());

            user_pub_key_map.put(u.getId(), pk);
            u.setW(w);
        }
        ProofVerifier pV = new ProofVerifier(pairing, new SHA256Digest());

        if (pV.verifyProof(proofs, c, user_pub_key_map, g)) {
            result += ("integrity verifies!");
        } else {
            result += ("file has been tampered");
        }

        return result;
    }
}
