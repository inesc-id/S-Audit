package homomorphic_authentication_library_Java.crypto.integrity_proofs.proof_verifier.optimized;

import homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.challenge.input.Challenge;
import homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.challenge.input.FileBlockChallenge;
import homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.challenge.input.FileChallenge;
import homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.challenge.input.UserChallenge;
import homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.proof.Proof;
import homomorphic_authentication_library_Java.homo_hashing.FileBlockHasher;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.Collection;
import java.util.HashMap;

import org.bouncycastle.crypto.Digest;

public class ProofVerifier {

    private Pairing pairing;
    private Digest digest;

    public ProofVerifier(Pairing p, Digest digest) {
        this.pairing = p;
        this.digest = digest;
    }

    public boolean verifyProof(Proof p,
                               Element w,
                               Element pub_key,
                               Element g,
                               Collection<FileChallenge> file_chals) {
        if (pub_key == null)
            throw new IllegalStateException("Invalid key.");

        Element alpha = pairing.getZr().newElementFromBytes(p.getAlpha());
        Element temp2 = calculatePairedAlpha(alpha, w, pub_key, file_chals);

        Element beta = pairing.getG1().newElementFromBytes(p.getBeta());
        Element temp1 = pairing.pairing(beta, g);

        return temp1.isEqual(temp2);
    }

    public boolean verifyProof(Collection<Proof> pl,
                               Challenge c,
                               HashMap<String, Element> user_pub_key_map,
                               Element g) {
        Element paired_alpha_ag = pairing.getGT().newElement();
        paired_alpha_ag.setToOne();
        Element beta = pairing.getG1().newElement();
        beta.setToOne();
        for (Proof p : pl) {

            String id = p.getUser();
            Element pub_key = user_pub_key_map.get(id);
            UserChallenge u_chal = c.getUser_challenge_set(id);
            Element alpha_p = pairing.getZr().newElementFromBytes(p.getAlpha());
            Element w_p = pairing.getG1().newElementFromBytes(u_chal.getW().toBytes());

            Element paired_alpha_ag_p =
                calculatePairedAlpha(alpha_p, w_p, pub_key, u_chal.getFiles());
            paired_alpha_ag.mul(paired_alpha_ag_p);


            Element beta_p = pairing.getG1().newElementFromBytes(p.getBeta());
            beta.mul(beta_p);
        }


        Element temp1 = calculatePairedBeta(g, beta);
        return temp1.isEqual(paired_alpha_ag);
    }


    private Element calculatePairedAlpha(Element alpha,
                                         Element w,
                                         Element pub_key,
                                         Collection<FileChallenge> file_chals) {
        //alpha_hash= π_i (H(id_i)^chal_val) * w^alpha_i
        Element alpha_hash = pairing.getG1().newElement();
        alpha_hash.setToOne();

        //π_i (H(id_i)^chal_val)
        Element f_ids = pairing.getG1().newElement();
        f_ids.setToOne();
        for (FileChallenge f_c : file_chals) {
            String file_id = f_c.getId();
            //int granularity = FileBlockHasher.calculateGranularity(f_c.getGranularity(), f_c., blockSize);
            for (FileBlockChallenge b : f_c.getFile_blocks()) {
                //for (int i = 0; i < granularity; i++) {
                int index = b.getIndex();
                byte[] id_b = (file_id + index).getBytes();
                digest.reset();
                digest.update(id_b, 0, id_b.length);

                int digestSize = digest.getDigestSize();
                byte[] hash = new byte[digestSize];
                digest.doFinal(hash, 0);
                Element h = pairing.getG1().newElementFromHash(hash, 0, hash.length);

                Element chal = pairing.getZr().newElement(b.getChallenge_val());

                h.powZn(chal);

                f_ids.mul(h);
                //}
            }
        }
        alpha_hash.mul(f_ids);

        //w^alpha
        Element h_alpha = pairing.getG1().newElementFromBytes(w.toBytes());
        h_alpha.powZn(alpha);

        alpha_hash.mul(h_alpha);

        //e(alpha_hash, pub_key)
        Element temp2 = pairing.pairing(alpha_hash, pub_key);
        return temp2;
    }

    private Element calculatePairedBeta(Element g, Element beta) {
        return pairing.pairing(beta, g);
    }

    public boolean verifyGranularitProof(Proof p,
                                         Element w,
                                         Element pub_key,
                                         Element g,
                                         Collection<FileChallenge> file_chals) {
        if (pub_key == null)
            throw new IllegalStateException("Invalid key.");

        Element alpha = pairing.getZr().newElementFromBytes(p.getAlpha());
        Element temp2 = calculateGranularityPairedAlpha(alpha, w, pub_key, file_chals);

        Element beta = pairing.getG1().newElementFromBytes(p.getBeta());
        Element temp1 = pairing.pairing(beta, g);

        return temp1.isEqual(temp2);
    }

    public boolean verifyGranularityProof(Collection<Proof> pl,
                                          Challenge c,
                                          HashMap<String, Element> user_pub_key_map,
                                          Element g) {
        Element paired_alpha_ag = pairing.getGT().newElement();
        paired_alpha_ag.setToOne();
        Element beta = pairing.getG1().newElement();
        beta.setToOne();
        for (Proof p : pl) {

            String id = p.getUser();
            Element pub_key = user_pub_key_map.get(id);
            UserChallenge u_chal = c.getUser_challenge_set(id);
            Element alpha_p = pairing.getZr().newElementFromBytes(p.getAlpha());
            Element w_p = pairing.getG1().newElementFromBytes(u_chal.getW().toBytes());

            Element paired_alpha_ag_p =
                calculateGranularityPairedAlpha(alpha_p, w_p, pub_key, u_chal.getFiles());
            paired_alpha_ag.mul(paired_alpha_ag_p);


            Element beta_p = pairing.getG1().newElementFromBytes(p.getBeta());
            beta.mul(beta_p);
        }


        Element temp1 = calculatePairedBeta(g, beta);
        return temp1.isEqual(paired_alpha_ag);
    }


    private Element calculateGranularityPairedAlpha(Element alpha,
                                                    Element w,
                                                    Element pub_key,
                                                    Collection<FileChallenge> file_chals) {
        //alpha_hash= π_i (H(id_i)^chal_val) * w^alpha_i
        Element alpha_hash = pairing.getG1().newElement();
        alpha_hash.setToOne();

        //π_i (H(id_i)^chal_val)
        Element f_ids = pairing.getG1().newElement();
        f_ids.setToOne();
        for (FileChallenge f_c : file_chals) {
            String file_id = f_c.getId();
            //int granularity = FileBlockHasher.calculateGranularity(f_c.getGranularity(), f_c., blockSize);
            if (f_c.getFile_blocks().isEmpty()) {
                int num_ids = (int) (1 / f_c.getGranularity());
                if ((int) (1 / f_c.getGranularity()) >= 0) {
                    num_ids++;
                }
                for (int index = 0; index < num_ids; index++) {
                    //for (int i = 0; i < granularity; i++) {
                    byte[] id_b = (file_id + index).getBytes();
                    digest.reset();
                    digest.update(id_b, 0, id_b.length);

                    int digestSize = digest.getDigestSize();
                    byte[] hash = new byte[digestSize];
                    digest.doFinal(hash, 0);
                    Element h = pairing.getG1().newElementFromHash(hash, 0, hash.length);

                    Element chal = pairing.getZr().newElement(f_c.getGlobalChallenge());

                    h.powZn(chal);

                    f_ids.mul(h);
                    //}
                }
            } else {
                for (FileBlockChallenge b : f_c.getFile_blocks()) {
                    //for (int i = 0; i < granularity; i++) {
                    int index = b.getIndex();
                    byte[] id_b = (file_id + index).getBytes();
                    digest.reset();
                    digest.update(id_b, 0, id_b.length);

                    int digestSize = digest.getDigestSize();
                    byte[] hash = new byte[digestSize];
                    digest.doFinal(hash, 0);
                    Element h = pairing.getG1().newElementFromHash(hash, 0, hash.length);

                    Element chal = pairing.getZr().newElement(b.getChallenge_val());

                    h.powZn(chal);

                    f_ids.mul(h);
                    //}
                }
            }
        }
        alpha_hash.mul(f_ids);

        //w^alpha
        Element h_alpha = pairing.getG1().newElementFromBytes(w.toBytes());
        h_alpha.powZn(alpha);

        alpha_hash.mul(h_alpha);

        //e(alpha_hash, pub_key)
        Element temp2 = pairing.pairing(alpha_hash, pub_key);
        return temp2;
    }
}
