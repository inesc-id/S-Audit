package storage_integrity_verifier.json;

import homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.proof.Proof;
import homomorphic_authentication_library_Java.io.ElementConversionTool;

import java.util.ArrayList;
import java.util.Collection;

import com.amazonaws.util.json.JSONArray;
import com.amazonaws.util.json.JSONException;
import com.amazonaws.util.json.JSONObject;

public class ProofJSONConvertor {

    public ProofJSONConvertor() {
        // TODO Auto-generated constructor stub
    }

    public static Collection<Proof> jSONToProof(JSONObject input) {
        Collection<Proof> p_list = new ArrayList<Proof>();
        try {
            JSONArray ar = input.getJSONArray("proofs");
            for (int i = 0; i < ar.length(); i++) {
                JSONObject o = ar.getJSONObject(i);

                String id = o.getString("id");
                byte[] alpha = ElementConversionTool.convertStringToBytes(o.getString("alpha"));
                byte[] beta = ElementConversionTool.convertStringToBytes(o.getString("beta"));

                Proof p = new Proof(alpha, beta, id);
                p_list.add(p);
            }
            return p_list;
        } catch (JSONException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        }
    }
}
