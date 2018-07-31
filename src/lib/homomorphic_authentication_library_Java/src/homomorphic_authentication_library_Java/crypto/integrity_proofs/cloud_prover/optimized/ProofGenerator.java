package homomorphic_authentication_library_Java.crypto.integrity_proofs.cloud_prover.optimized;

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
import homomorphic_authentication_library_Java.homo_hashing.FileBlockHasher;
import homomorphic_authentication_library_Java.io.DataManipulator;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.Point;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.GeneralDigest;

class ProofGenerator {
    private Pairing pairing;
    private Digest digest;

    ProofGenerator(Digest digest, Pairing p) {
        this.pairing = p;
        this.digest = digest;
        this.digest.reset();
    }

    Collection<Proof> generateProof(Challenge c, HashMap<String, UserAuditingObject> user_data) {
        Collection<Proof> p_list = new ArrayList<Proof>();
        Collection<UserChallenge> u_c_list =
            new ArrayList<UserChallenge>(c.getUser_challenge_set());

        for (UserChallenge u_c : u_c_list) {
            Proof p = calculateUserProof(u_c, user_data.get(u_c.getId()));
            p_list.add(p);
        }

        return p_list;
    }

    private Proof calculateUserProof(UserChallenge c, UserAuditingObject user_data) {
        byte[] alpha = calculateAlpha(c, user_data);
        byte[] beta = calculateBeta(c, user_data);
        String id = c.getId();

        Proof p = new Proof(alpha, beta, id);
        return p;
    }

    private byte[] calculateAlpha(UserChallenge c, UserAuditingObject user_data) {
        Element alpha = null;
        for (FileChallenge f_c : c.getFiles()) {
            FileAuditingObject f = user_data.getFile(f_c.getId());
            /*int granularity = FileBlockHasher.calculateGranularity(f_c.getGranularity(),
                    f.getFileSize(), pairing.getZr().getLengthInBytes());*/
            BlockAuditingObject b_o = user_data.getFile(f_c.getId()).getBlocks();
            if (f_c.getFile_blocks().isEmpty()) {
                int n = b_o.getNumBlocks();
                int r_c = f_c.getGlobalChallenge();
                Element chal = pairing.getZr().newElement(r_c);
                for (int i = 0; i < n; i++) {

                    byte[] block_content = b_o.getBlock_content(i);
                    byte[][] l = DataManipulator.split_message(block_content,
                            pairing.getZr().getLengthInBytes());
                    for (byte[] s : l) {
                        Element h_mk = pairing.getZr().newElementFromHash(s, 0, s.length);

                        Element alpha_f_c = pairing.getZr().newElement();
                        alpha_f_c.setToOne();
                        alpha_f_c.mul(chal);
                        alpha_f_c.mul(h_mk);
                        if (alpha == null) {
                            alpha = alpha_f_c;
                        } else {
                            alpha.add(alpha_f_c);
                        }
                    }
                }
            } else {
                for (FileBlockChallenge b : f_c.getFile_blocks()) {
                    int r_c = b.getChallenge_val();
                    Element chal = pairing.getZr().newElement(r_c);

                    byte[] block_content = b_o.getBlock_content(b.getIndex());
                    byte[][] l = DataManipulator.split_message(block_content,
                            pairing.getZr().getLengthInBytes());
                    for (byte[] s : l) {
                        Element h_mk = pairing.getZr().newElementFromHash(s, 0, s.length);

                        Element alpha_f_c = pairing.getZr().newElement();
                        alpha_f_c.setToOne();
                        alpha_f_c.mul(chal);
                        alpha_f_c.mul(h_mk);
                        if (alpha == null) {
                            alpha = alpha_f_c;
                        } else {
                            alpha.add(alpha_f_c);
                        }
                    }
                }
            }
        }
        return alpha.toBytes();
    }

    private byte[] calculateBeta(UserChallenge c, UserAuditingObject user_data) {
        Element beta = null;
        for (FileChallenge f_c : c.getFiles()) {
            BlockAuditingObject b_o = user_data.getFile(f_c.getId()).getBlocks();

            if (f_c.getFile_blocks().isEmpty()) {
                int n = b_o.getNumBlocks();
                int r_c = f_c.getGlobalChallenge();
                Element chal = pairing.getZr().newElement(r_c);
                for (int i = 0; i < n; i++) {
                    byte[] sig_content = b_o.getSignature(i);

                    Point sigP = (Point) pairing.getG1().newElement();
                    int val = sigP.setFromBytesCompressed(sig_content);

                    Element beta_f_c = pairing.getG1().newElement(sigP);
                    beta_f_c.powZn(chal);
                    if (beta == null) {
                        beta = beta_f_c;
                    } else {
                        beta.mul(beta_f_c);
                    }
                }
            } else {
                for (FileBlockChallenge b : f_c.getFile_blocks()) {
                    int r_c = b.getChallenge_val();
                    Element chal = pairing.getZr().newElement(r_c);
                    byte[] sig_content = b_o.getSignature(b.getIndex());

                    Point sigP = (Point) pairing.getG1().newElement();
                    int val = sigP.setFromBytesCompressed(sig_content);

                    Element beta_f_c = pairing.getG1().newElement(sigP);

                    beta_f_c.powZn(chal);

                    if (beta == null) {
                        beta = beta_f_c;
                    } else {
                        beta.mul(beta_f_c);
                    }
                }
            }
        }
        return beta.toBytes();
    }

    public Collection<Proof> generateProof(AuditingRequest req) {
        Collection<Proof> p_list = new ArrayList<Proof>();
        Collection<UserChallenge> u_c_list = req.getChallenge().getUser_challenge_set();
        AuditingData u = req.getData();
        for (UserChallenge u_c : u_c_list) {
            Proof p = calculateUserProof(u_c, u.getUser(u_c.getId()));
            p_list.add(p);
        }

        return p_list;
    }

    public Collection<Proof> generateHashedProof(AuditingRequest req, GeneralDigest d) {
        Collection<Proof> p_list = new ArrayList<Proof>();
        Collection<UserChallenge> u_c_list = req.getChallenge().getUser_challenge_set();
        AuditingData u = req.getData();
        for (UserChallenge u_c : u_c_list) {
            Proof p = calculateHashedUserProof(u_c, u.getUser(u_c.getId()), d);
            p_list.add(p);
        }

        return p_list;
    }

    private Proof calculateHashedUserProof(UserChallenge c,
                                           UserAuditingObject user_data,
                                           GeneralDigest d) {
        byte[] alpha = calculateHashedAlpha(c, user_data, d);
        byte[] beta = calculateBeta(c, user_data);
        String id = c.getId();

        Proof p = new Proof(alpha, beta, id);
        return p;
    }

    private byte[] calculateHashedAlpha(UserChallenge c,
                                        UserAuditingObject user_data,
                                        GeneralDigest d) {
        Element alpha = pairing.getZr().newElement();
        alpha.setToZero();
        for (FileChallenge f_c : c.getFiles()) {
            FileAuditingObject f = user_data.getFile(f_c.getId());
            int granularity = FileBlockHasher.calculateGranularity(f_c.getGranularity(),
                    f.getFileSize(), pairing.getZr().getLengthInBytes());
            BlockAuditingObject b_o = user_data.getFile(f_c.getId()).getBlocks();
            if (f_c.getFile_blocks().isEmpty()) {
                int n = b_o.getNumBlocks();
                int r_c = f_c.getGlobalChallenge();
                Element chal = pairing.getZr().newElement(r_c);
                for (int i = 0; i < n; i++) {
                    //int granularity = b.getGranularity();
                    byte[] block_content = FileBlockHasher.hashFileBlocks(b_o.getBlock_content(i),
                            granularity, pairing.getZr().getLengthInBytes(), d);
                    byte[][] l = DataManipulator.split_message(block_content,
                            pairing.getZr().getLengthInBytes());
                    for (byte[] s : l) {
                        Element h_mk = pairing.getZr().newElementFromHash(s, 0, s.length);

                        Element alpha_f_c = pairing.getZr().newElement();
                        alpha_f_c.setToOne();
                        alpha_f_c.mul(chal);
                        alpha_f_c.mul(h_mk);
                        alpha.add(alpha_f_c);
                    }
                }
            } else {
                for (FileBlockChallenge b : f_c.getFile_blocks()) {
                    int r_c = b.getChallenge_val();
                    Element chal = pairing.getZr().newElement(r_c);

                    //int granularity = b.getGranularity();
                    byte[] block_content =
                        FileBlockHasher.hashFileBlocks(b_o.getBlock_content(b.getIndex()),
                                granularity, pairing.getZr().getLengthInBytes(), d);
                    byte[][] l = DataManipulator.split_message(block_content,
                            pairing.getZr().getLengthInBytes());
                    for (byte[] s : l) {
                        Element h_mk = pairing.getZr().newElementFromHash(s, 0, s.length);

                        Element alpha_f_c = pairing.getZr().newElement();
                        alpha_f_c.setToOne();
                        alpha_f_c.mul(chal);
                        alpha_f_c.mul(h_mk);
                        alpha.add(alpha_f_c);
                    }
                }
            }
        }
        return alpha.toBytes();
    }
}
