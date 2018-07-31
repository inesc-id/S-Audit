/*package homomorphic_authentication_cli;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import homomorphic_authentication_library_Java.crypto.FileIntegrityObject;
import homomorphic_authentication_library_Java.crypto.UserIntegrityObject;
import homomorphic_authentication_library_Java.crypto.bls_signature.BLS01;
import homomorphic_authentication_library_Java.crypto.bls_signature.PairingAGenerator;
import homomorphic_authentication_library_Java.crypto.integrity_proofs.challenge.Challenge;
import homomorphic_authentication_library_Java.crypto.integrity_proofs.challenge.FileChallenge;
import homomorphic_authentication_library_Java.crypto.integrity_proofs.challenge.UserChallenge;
import homomorphic_authentication_library_Java.crypto.integrity_proofs.cloud_prover.CloudProver;
import homomorphic_authentication_library_Java.crypto.integrity_proofs.proof.Proof;
import homomorphic_authentication_library_Java.crypto.integrity_proofs.proof_verifier.ProofVerifier;
import homomorphic_authentication_library_Java.io.ElementConversionTool;
import it.unisa.dia.gas.crypto.jpbc.signature.bls01.params.BLS01Parameters;
import it.unisa.dia.gas.crypto.jpbc.signature.bls01.params.BLS01PublicKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.security.SecureRandom;
import java.util.Collection;
import java.util.HashMap;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA256Digest;


public class Main {
    public static void main(String[] args) {
        ///////////////
        // Setup
        ///////////////
        PairingAGenerator pG = new PairingAGenerator(true);
        pG.generate();
        PairingParameters pairingParameters = pG.getPairingParameters();
        Pairing pairing = pG.getPairing();
        Element g = pG.getG();

        ///////////////
        //Tagging process
        ///////////////

        //Client0
        //generate global parameter w and keys
        Element w0 = pG.generateW();
        System.out.println("w0 : " + ElementConversionTool.convertElementToString(w0));
        BLS01 bls0 = new BLS01(pairingParameters, g, w0);
        AsymmetricCipherKeyPair keyPair0 = bls0.keyGen();

        //sign user files
        String message0_1 = "H";
        String id0_1 = "file0_1.txt";
        byte[] sig0_1 = bls0.sign(message0_1, id0_1, keyPair0.getPrivate());
        System.out
                .println("file0_1.txt.sig: " + ElementConversionTool.convertBytesToString(sig0_1));
        String message0_2 = "Hello!";
        String id0_2 = "file0_2.txt";
        byte[] sig0_2 = bls0.sign(message0_2, id0_2, keyPair0.getPrivate());

        //verify
        assertSignatureGeneration(bls0, keyPair0, message0_1, id0_1, sig0_1);
        assertSignatureGeneration(bls0, keyPair0, message0_2, id0_2, sig0_2);

        //Client1
        //generate global parameter w and keys
        Element w1 = pG.generateW();
        BLS01 bls1 = new BLS01(pairingParameters, g, w1);
        AsymmetricCipherKeyPair keyPair1 = bls1.keyGen();

        //sign user files
        String message1_1 = "client 1!";
        String id1_1 = "file1_1.txt";
        byte[] sig1_1 = bls1.sign(message1_1, id1_1, keyPair1.getPrivate());
        String message1_2 = "Say hello to my little friend!";
        String id1_2 = "file1_2.txt";
        byte[] sig1_2 = bls1.sign(message1_2, id1_2, keyPair1.getPrivate());

        //verify
        assertSignatureGeneration(bls1, keyPair1, message1_1, id1_1, sig1_1);
        assertSignatureGeneration(bls1, keyPair1, message1_2, id1_2, sig1_2);

        ///////////////
        //FS representation construction
        ///////////////

        //Create Users
        HashMap<String, UserIntegrityObject> user_map = new HashMap<>();

        UserIntegrityObject u0 = new UserIntegrityObject("0", bls0.getW());
        u0.addFile(sig0_1, message0_1.getBytes(), id0_1);
        u0.addFile(sig0_2, message0_2.getBytes(), id0_2);
        user_map.put("0", u0);

        UserIntegrityObject u1 = new UserIntegrityObject("1", bls1.getW());
        u1.addFile(sig1_1, message1_1.getBytes(), id1_1);
        u1.addFile(sig1_2, message1_2.getBytes(), id1_2);
        user_map.put("1", u1);

        //creating user public key map
        HashMap<String, Element> user_pub_key_map = new HashMap<>();
        BLS01PublicKeyParameters param_0 = (BLS01PublicKeyParameters) keyPair0.getPublic();
        user_pub_key_map.put("0", param_0.getPk());
        BLS01PublicKeyParameters param_1 = (BLS01PublicKeyParameters) keyPair1.getPublic();
        user_pub_key_map.put("1", param_1.getPk());

        ///////////////
        //Challenge process
        ///////////////

        CloudProver c_p = new CloudProver(pairing);
        ProofVerifier p_v = new ProofVerifier(pairing, new SHA256Digest());


        //positive test
        Challenge good_c = generateChallenge(user_map);
        Collection<Proof> p_list = c_p.generateProof(good_c);
        assertTrueProofGeneration(good_c, p_list, p_v, user_pub_key_map, param_0, param_1, g);

        Challenge bad_c;
        Collection<Proof> bad_p_list;
        //negative test1
        bad_c = generateTamperedChallenge(good_c, "0", id0_1);
        bad_p_list = c_p.generateProof(bad_c);
        assertFalseProofGeneration(bad_c, bad_p_list, p_v, user_pub_key_map, param_0, param_1, g);
        //negative test2
        bad_c = generateTamperedChallenge(good_c, "0", id0_2);
        bad_p_list = c_p.generateProof(bad_c);
        assertFalseProofGeneration(bad_c, bad_p_list, p_v, user_pub_key_map, param_0, param_1, g);
        //negative test3
        bad_c = generateTamperedChallenge(bad_c, "1", id1_1);
        bad_p_list = c_p.generateProof(bad_c);
        assertFalseProofGeneration(bad_c, bad_p_list, p_v, user_pub_key_map, param_0, param_1, g);
        //negative test4
        bad_c = generateTamperedChallenge(bad_c, "1", id1_2);
        bad_p_list = c_p.generateProof(bad_c);
        assertFalseProofGeneration(bad_c, bad_p_list, p_v, user_pub_key_map, param_0, param_1, g);


        System.out.println("key size: " + g.getLengthInBytes());
    }

    private static Challenge generateChallenge(HashMap<String, UserIntegrityObject> user_map) {
        SecureRandom sR = new SecureRandom();
        Challenge good_c = new Challenge();
        for (UserIntegrityObject u : user_map.values()) {
            UserChallenge u_c = new UserChallenge(u.getId(), u.getW());
            for (FileIntegrityObject f : u.getFiles()) {
                int chal = sR.nextInt();
                u_c.addFileChallenge(chal, f);
            }
            good_c.addUserChallenge(u.getId(), u_c);
        }
        return good_c;
    }

    private static int discoverMaxMessageLength(AsymmetricCipherKeyPair keyPair0, BLS01 bls01) {
        // TODO Auto-generated method stub
        String message0_1 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        String id0_1 = "file0_1.txt";

        while (true) {
            byte[] sig0_1 = bls01.sign(message0_1, id0_1, keyPair0.getPrivate());
            try {
                System.out.println("testing " + message0_1.length());
                // Test same message
                if (!bls01.verify(sig0_1, message0_1, id0_1, keyPair0.getPublic()))
                    break;

                // Test different messages
                if (bls01.verify(sig0_1, message0_1 + "a", id0_1, keyPair0.getPublic()))
                    break;

                message0_1 += "aaaaaaaa";
            } catch (Exception o) {
                break;
            }
        }

        return message0_1.length();
    }


    private static Challenge generateTamperedChallenge(Challenge c,
                                                       String userToTamper,
                                                       String file_to_Tamper) {
        Challenge bad_c = new Challenge();
        for (UserChallenge u : c.getUser_challenge_set()) {
            UserChallenge u_c = new UserChallenge(u.getId(), u.getW());
            for (FileChallenge f : u.getFiles()) {
                if (u_c.getId().equals(userToTamper)
                        && f.getFile().getFileId().equals(file_to_Tamper)) {
                    int chal = f.getRandom_chal();
                    byte[] message_content = f.getFile().getFileContent();
                    byte[] a = "a".getBytes();
                    byte[] tamperedContent = concatenate_byte_arrays(message_content, a);

                    String id = f.getFile().getFileId();
                    byte[] sig = f.getFile().getSignature();
                    u_c.addFileChallenge(chal, id, tamperedContent, sig);
                } else {
                    u_c.addFileChallenge(f.getRandom_chal(), f.getFile());
                }
            }
            bad_c.addUserChallenge(u.getId(), u_c);
        }
        return bad_c;
    }

    private static byte[] concatenate_byte_arrays(byte[] message_content, byte[] a) {
        byte[] tamperedContent = new byte[message_content.length + a.length];
        // create a destination array that is the size of the two arrays
        // copy message_content into start of destination (from pos 0, copy message_content.length bytes)
        System.arraycopy(message_content, 0, tamperedContent, 0, message_content.length);

        // copy a into end of destination (from pos message_content.length, copy a.length bytes)
        System.arraycopy(a, 0, tamperedContent, message_content.length, a.length);
        return tamperedContent;
    }

    private static void assertTrueProofGeneration(Challenge c,
                                                  Collection<Proof> p_list,
                                                  ProofVerifier p_v,
                                                  HashMap<String, Element> user_pub_key_map,
                                                  BLS01PublicKeyParameters param_0,
                                                  BLS01PublicKeyParameters param_1,
                                                  Element g) {
        assertTrue(p_v.verifyProof(p_list, c, user_pub_key_map, g));
        for (Proof pr : p_list) {
            Collection<FileChallenge> f_c = c.getUser_challenge_set(pr.getUser()).getFiles();
            assertTrue(p_v.verifyProof(pr, c.getUser_challenge_set(pr.getUser()).getW(),
                    user_pub_key_map.get(pr.getUser()), g, f_c));
        }
    }

    private static void assertFalseProofGeneration(Challenge c,
                                                   Collection<Proof> p_list,
                                                   ProofVerifier p_v,
                                                   HashMap<String, Element> user_pub_key_map,
                                                   BLS01PublicKeyParameters param_0,
                                                   BLS01PublicKeyParameters param_1,
                                                   Element g) {
        assertFalse(p_v.verifyProof(p_list, c, user_pub_key_map, g));
    }

    private static void assertSignatureGeneration(BLS01 bls01,
                                                  AsymmetricCipherKeyPair keyPair,
                                                  String message,
                                                  String id,
                                                  byte[] sig) {
        // Test same message
        assertTrue(bls01.verify(sig, message, id, keyPair.getPublic()));

        // Test different messages
        assertFalse(bls01.verify(sig, "Hello Italy!", id, keyPair.getPublic()));
    }
}
*/
