package homomorphic_authentication_library_Java.crypto.integrity_proofs.cloud_prover;

import homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.challenge.data.AuditingRequest;
import homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.challenge.data.UserAuditingObject;
import homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.challenge.input.Challenge;
import homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.proof.Proof;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.Collection;
import java.util.HashMap;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.GeneralDigest;
import org.bouncycastle.crypto.digests.SHA256Digest;

public class CloudProver {
    private Pairing p;

    public CloudProver(Pairing p) {
        this.p = p;
    }

    public Collection<Proof> generateProof(Challenge challenge,
                                           HashMap<String, UserAuditingObject> user_data) {
        ProofGenerator g = new ProofGenerator(new SHA256Digest(), p);

        Collection<Proof> l = g.generateProof(challenge, user_data);

        return l;
    }

    public Collection<Proof> generateProof(AuditingRequest req) {
        ProofGenerator g = new ProofGenerator(new SHA256Digest(), p);

        Collection<Proof> l = g.generateProof(req);

        return l;
    }

    public Collection<Proof> generateHashedProof(AuditingRequest req, GeneralDigest d) {
        ProofGenerator g = new ProofGenerator(new SHA256Digest(), p);

        Collection<Proof> l = g.generateHashedProof(req, d);

        return l;
    }
}
