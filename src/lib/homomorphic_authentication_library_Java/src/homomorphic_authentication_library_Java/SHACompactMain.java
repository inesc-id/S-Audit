package homomorphic_authentication_library_Java;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Collection;
import java.util.HashMap;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;

import homomorphic_authentication_library_Java.crypto.bls_signature.BLS;
import homomorphic_authentication_library_Java.crypto.integrity_proofs.cloud_prover.CloudProver;
import homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.challenge.data.AuditingData;
import homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.challenge.data.AuditingRequest;
import homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.challenge.data.BlockAuditingObject;
import homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.challenge.data.FileAuditingObject;
import homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.challenge.data.UserAuditingObject;
import homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.challenge.input.Challenge;
import homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.challenge.input.FileBlockChallenge;
import homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.challenge.input.FileChallenge;
import homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.challenge.input.UserChallenge;
import homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.proof.Proof;
import homomorphic_authentication_library_Java.crypto.integrity_proofs.proof_verifier.ProofVerifier;
import homomorphic_authentication_library_Java.crypto.pairing.PairingAGenerator;
import homomorphic_authentication_library_Java.homo_hashing.FileBlockHasher;
import homomorphic_authentication_library_Java.io.DataManipulator;
import homomorphic_authentication_library_Java.io.ElementConversionTool;
import homomorphic_authentication_library_Java.io.FileSystemHandler;
import it.unisa.dia.gas.crypto.jpbc.signature.bls01.params.BLS01PrivateKeyParameters;
import it.unisa.dia.gas.crypto.jpbc.signature.bls01.params.BLS01PublicKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;


public class SHACompactMain {
    public static void main(String[] args) {

        double granularity = 50.0;
        String str = "HELLO";
        System.out.println(ElementConversionTool.convertBytesToString(str.getBytes()));
        byte[][] str_split = DataManipulator.split_message(str, 2);
        byte[] str_byte = DataManipulator.aggregateDataBlocks(2, str_split);
        System.out.println(ElementConversionTool.convertBytesToString(str_byte));

        ///////////////
        // Setup
        ///////////////
        PairingAGenerator pG = new PairingAGenerator(160, 512);
        pG.generate();
        PairingParameters pairingParameters = pG.getPairingParameters();
        Pairing pairing = pG.getPairing();
        Element g = pG.getG();

        String m =
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        int granularity_int = FileBlockHasher.calculateGranularity(granularity, m.getBytes().length,
                pairing.getZr().getLengthInBytes());
        byte[] hashes = FileBlockHasher.hashFileBlocks(m.getBytes(), granularity_int,
                pairing.getZr().getLengthInBytes(), new SHA1Digest());
        //byte[] m1 = DataManipulator.aggregateDataBlocks(pairing.getZr().getLengthInBytes(), hashes);

        ///////////////
        //Tagging process
        ///////////////

        //Client0
        //generate global parameter w and keys
        Element w0 = pG.generateW();
        System.out.println("w0 : " + ElementConversionTool.convertElementToString(w0));
        BLS bls0 = new BLS(pairingParameters, g, w0);
        AsymmetricCipherKeyPair keyPair0 = bls0.keyGen();

        //sign user files
        String message0_1 = "HAAAAAAAAAAAAAAAAAAAAAAAAAA";
        granularity_int = FileBlockHasher.calculateGranularity(granularity,
                message0_1.getBytes().length, pairing.getZr().getLengthInBytes());
        byte[] hash_message0_1 = FileBlockHasher.hashFileBlocks(message0_1.getBytes(),
                granularity_int, pairing.getZr().getLengthInBytes(), new SHA1Digest());
        String id0_1 = "file0_1.txt";
        byte[][] sig0_1 = null;
        try {
            sig0_1 = bls0.sign(hash_message0_1, id0_1, keyPair0.getPrivate());
        } catch (DataLengthException e2) {
            // TODO Auto-generated catch block
            e2.printStackTrace();
        }
        System.out.println(
                "file0_1.txt.sig: " + ElementConversionTool.convertBytesToString(sig0_1[0]));
        String message0_2 = "Hello!";
        granularity_int = FileBlockHasher.calculateGranularity(granularity,
                message0_2.getBytes().length, pairing.getZr().getLengthInBytes());
        byte[] hash_message0_2 = FileBlockHasher.hashFileBlocks(message0_2.getBytes(),
                granularity_int, pairing.getZr().getLengthInBytes(), new SHA1Digest());
        String id0_2 = "file0_2.txt";
        byte[][] sig0_2 = null;
        try {
            sig0_2 = bls0.sign(hash_message0_2, id0_2, keyPair0.getPrivate());
        } catch (DataLengthException e2) {
            // TODO Auto-generated catch block
            e2.printStackTrace();
        }

        //verify
        assertSignatureGeneration(bls0, keyPair0, hash_message0_1, id0_1, sig0_1);
        assertSignatureGeneration(bls0, keyPair0, hash_message0_2, id0_2, sig0_2);

        //Client1
        //generate global parameter w and keys
        Element w1 = pG.generateW();
        BLS bls1 = new BLS(pairingParameters, g, w1);
        AsymmetricCipherKeyPair keyPair1 = bls1.keyGen();

        //sign user files
        String message1_1 = "client 1!";
        granularity_int = FileBlockHasher.calculateGranularity(granularity,
                message1_1.getBytes().length, pairing.getZr().getLengthInBytes());
        byte[] hash_message1_1 = FileBlockHasher.hashFileBlocks(message1_1.getBytes(),
                granularity_int, pairing.getZr().getLengthInBytes(), new SHA1Digest());
        String id1_1 = "file1_1.txt";
        byte[][] sig1_1 = null;
        try {
            sig1_1 = bls1.sign(hash_message1_1, id1_1, keyPair1.getPrivate());
        } catch (DataLengthException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }
        String message1_2 = "Say hello to my little friend!";
        granularity_int = FileBlockHasher.calculateGranularity(granularity,
                message1_2.getBytes().length, pairing.getZr().getLengthInBytes());
        byte[] hash_message1_2 = FileBlockHasher.hashFileBlocks(message1_2.getBytes(),
                granularity_int, pairing.getZr().getLengthInBytes(), new SHA1Digest());
        String id1_2 = "file1_2.txt";
        byte[][] sig1_2 = null;
        try {
            sig1_2 = bls1.sign(hash_message1_2, id1_2, keyPair1.getPrivate());
        } catch (DataLengthException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }
        //verify
        assertSignatureGeneration(bls1, keyPair1, hash_message1_1, id1_1, sig1_1);
        assertSignatureGeneration(bls1, keyPair1, hash_message1_2, id1_2, sig1_2);

        ///////////////
        //FS representation construction
        ///////////////

        //Create Users
        HashMap<String, UserAuditingObject> user_map = new HashMap<>();

        UserAuditingObject u0 = new UserAuditingObject("0", bls0.getW());

        granularity_int = FileBlockHasher.calculateGranularity(granularity,
                message0_1.getBytes().length, pairing.getZr().getLengthInBytes());
        FileAuditingObject f_0_1 = new FileAuditingObject(id0_1, message0_1.getBytes().length,
                pairing.getZr().getLengthInBytes() * granularity_int, granularity);
        BlockAuditingObject b_0_1 = f_0_1.getBlocks();
        byte[][] blocks_0_1 = DataManipulator.split_message(message0_1.getBytes(),
                granularity_int * pairing.getZr().getLengthInBytes());
        b_0_1.setAllBlocks(blocks_0_1, sig0_1);

        granularity_int = FileBlockHasher.calculateGranularity(granularity,
                message0_2.getBytes().length, pairing.getZr().getLengthInBytes());
        FileAuditingObject f_0_2 = new FileAuditingObject(id0_2, message0_2.getBytes().length,
                pairing.getZr().getLengthInBytes() * granularity_int, granularity);
        BlockAuditingObject b_0_2 = f_0_2.getBlocks();
        byte[][] blocks_0_2 = DataManipulator.split_message(message0_2.getBytes(),
                granularity_int * pairing.getZr().getLengthInBytes());
        b_0_2.setAllBlocks(blocks_0_2, sig0_2);

        u0.addFile(id0_1, f_0_1);
        u0.addFile(id0_2, f_0_2);
        user_map.put("0", u0);

        UserAuditingObject u1 = new UserAuditingObject("1", bls1.getW());

        granularity_int = FileBlockHasher.calculateGranularity(granularity,
                message1_1.getBytes().length, pairing.getZr().getLengthInBytes());
        FileAuditingObject f_1_1 = new FileAuditingObject(id1_1, message1_1.getBytes().length,
                pairing.getZr().getLengthInBytes() * granularity_int, granularity);
        BlockAuditingObject b_1_1 = f_1_1.getBlocks();
        byte[][] blocks_1_1 = DataManipulator.split_message(message1_1.getBytes(),
                granularity_int * pairing.getZr().getLengthInBytes());
        b_1_1.setAllBlocks(blocks_1_1, sig1_1);

        granularity_int = FileBlockHasher.calculateGranularity(granularity,
                message1_2.getBytes().length, pairing.getZr().getLengthInBytes());
        FileAuditingObject f_1_2 = new FileAuditingObject(id1_2, message1_2.getBytes().length,
                pairing.getZr().getLengthInBytes() * granularity_int, granularity);
        BlockAuditingObject b_1_2 = f_1_2.getBlocks();
        byte[][] blocks_1_2 = DataManipulator.split_message(message1_2.getBytes(),
                granularity_int * pairing.getZr().getLengthInBytes());
        b_1_2.setAllBlocks(blocks_1_2, sig1_2);

        u1.addFile(id1_1, f_1_1);
        u1.addFile(id1_2, f_1_2);
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
        AuditingRequest req = new AuditingRequest(good_c, new AuditingData(user_map));
        Collection<Proof> p_list = c_p.generateHashedProof(req, new SHA1Digest());
        assertTrueProofGeneration(good_c, p_list, p_v, user_pub_key_map, param_0, param_1, g);

        Challenge bad_c;
        Collection<Proof> bad_p_list;
        /*
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
        */

        System.out.println("key size: " + g.getLengthInBytes());

        System.out.println("private key:"
                + ((Element) ((BLS01PrivateKeyParameters) keyPair0.getPrivate()).getSk())
                        .getLengthInBytes());
        System.out.println("public key:"
                + ((Element) ((BLS01PublicKeyParameters) keyPair0.getPublic()).getPk())
                        .getLengthInBytes());
        System.out.println(discoverMaxMessageLength(keyPair0, bls0));
        System.out.println(pairing.getG1().getLengthInBytes());
        System.out.println(pairing.getG2().getLengthInBytes());
        System.out.println(pairing.getGT().getLengthInBytes());
        System.out.println(pairing.getZr().getLengthInBytes());

        System.out.println("testing messages bigger than key:");
        //sign user files
        String message0_1_block = "AAAAAAAAAAAAAAAAAAA";
        String id0_1_block = "file0_1.txt";
        byte[][] sig0_1_block = null;
        try {
            sig0_1_block = bls0.sign(message0_1_block, id0_1_block, keyPair0.getPrivate());
        } catch (DataLengthException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }
        System.out.println("file0_1.txt.sig length: " + sig0_1_block.length);
        assertTrue(bls0.verify(sig0_1_block, message0_1_block, id0_1_block, param_0));
        assertFalse(bls0.verify(sig0_1_block, message0_1_block + "A", id0_1_block, param_0));

        //sign user files
        String message0_2_block =
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        granularity_int = FileBlockHasher.calculateGranularity(granularity,
                message0_2_block.getBytes().length, pairing.getZr().getLengthInBytes());
        byte[] hash_message0_2_block = FileBlockHasher.hashFileBlocks(message0_1.getBytes(),
                granularity_int, pairing.getZr().getLengthInBytes(), new SHA1Digest());
        String id0_2_block = "file0_1.txt";
        System.out.println("message size: " + message0_2_block.length());
        byte[][] sig0_2_block = null;
        try {
            sig0_2_block = bls0.sign(hash_message0_2_block, id0_2_block, keyPair0.getPrivate());
        } catch (DataLengthException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }
        System.out.println("num blocks length: " + sig0_2_block.length);
        System.out.println("chunk: " + sig0_2_block[0].length);
        System.out.println("last chunk: " + sig0_2_block[sig0_2_block.length - 1].length);
        assertTrue(bls0.verify(sig0_2_block, hash_message0_2_block, id0_2_block, param_0));
        assertFalse(bls0.verify(sig0_2_block, hash_message0_2_block + "A", id0_2_block, param_0));


        System.out.println(sig0_1[0].length);
        byte[] ag =
            DataManipulator.aggregateDataBlocks(pairing.getG1().getLengthInBytes(), sig0_2_block);
        System.out.println(ElementConversionTool.convertBytesToString(ag));
        System.out.println(ag.length);

        try {
            FileSystemHandler.writeFile("ag.sig", ag);
            byte[] res = FileSystemHandler.readFileBytes("ag.sig");
            assertTrue(bls0.verify(sig0_2_block, hash_message0_2_block, id0_2_block, param_0));
            assertFalse(bls0.verify(res, hash_message0_2_block + "A", id0_2_block, param_0));
        } catch (IOException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }
    }

    private static Challenge generateChallenge(HashMap<String, UserAuditingObject> user_map) {
        SecureRandom sR = new SecureRandom();
        Challenge good_c = new Challenge();
        for (UserAuditingObject u : user_map.values()) {
            UserChallenge u_c = new UserChallenge(u.getId(), u.getW());
            for (FileAuditingObject f : u.getFiles()) {
                FileChallenge f_c = new FileChallenge(f.getId(), f.getGranularity());
                Collection<Integer> indexes = f.getIndexes();
                BlockAuditingObject blocks = f.getBlocks();
                if (indexes.isEmpty()) {
                    for (int i = 0; i < blocks.getNumBlocks(); i++) {
                        FileBlockChallenge f_b_c = new FileBlockChallenge(i, sR.nextInt());
                        f_c.addFileBlock(f_b_c);
                    }
                } else {
                    for (int i : indexes) {
                        FileBlockChallenge f_b_c = new FileBlockChallenge(i, sR.nextInt());
                        f_c.addFileBlock(f_b_c);
                    }
                }
                u_c.addFileChallenge(f_c);
            }
            good_c.addUserChallenge(u.getId(), u_c);
        }
        return good_c;
    }

    private static int discoverMaxMessageLength(AsymmetricCipherKeyPair keyPair0, BLS bls01) {
        // TODO Auto-generated method stub
        String message0_1 = "aaaaaaaaaaaaaaaaaaa";
        String id0_1 = "file0_1.txt";

        while (true) {
            byte[][] sig0_1 = null;
            try {
                sig0_1 = bls01.sign(message0_1, id0_1, keyPair0.getPrivate());
            } catch (DataLengthException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            try {
                System.out.println("testing " + message0_1.length());
                // Test same message
                if (!bls01.verify(sig0_1[0], message0_1, id0_1, keyPair0.getPublic()))
                    break;

                // Test different messages
                if (bls01.verify(sig0_1[0], message0_1 + "a", id0_1, keyPair0.getPublic()))
                    break;

                message0_1 += "a";
            } catch (Exception o) {
                break;
            }
        }

        return message0_1.length();
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

    private static void assertSignatureGeneration(BLS bls01,
                                                  AsymmetricCipherKeyPair keyPair,
                                                  String message,
                                                  String id,
                                                  byte[] sig) {
        // Test same message
        assertTrue(bls01.verify(sig, message, id, keyPair.getPublic()));

        // Test different messages
        assertFalse(bls01.verify(sig, "Hello Italy!", id, keyPair.getPublic()));
    }

    private static void assertSignatureGeneration(BLS bls01,
                                                  AsymmetricCipherKeyPair keyPair,
                                                  byte[] message,
                                                  String id,
                                                  byte[][] sig) {
        // Test same message
        assertTrue(bls01.verify(sig, message, id, keyPair.getPublic()));

        // Test different messages
        assertFalse(bls01.verify(sig, "Hello Italy!", id, keyPair.getPublic()));
    }
}
