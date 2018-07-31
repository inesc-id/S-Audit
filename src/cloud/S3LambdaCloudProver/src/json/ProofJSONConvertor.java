package json;

import homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.proof.Proof;
import homomorphic_authentication_library_Java.io.ElementConversionTool;

import java.util.Collection;

import com.amazonaws.util.json.JSONArray;
import com.amazonaws.util.json.JSONException;
import com.amazonaws.util.json.JSONObject;

public class ProofJSONConvertor {

    public ProofJSONConvertor() {
        // TODO Auto-generated constructor stub
    }

    public JSONObject proofToJSON(Collection<Proof> p_list) {
        try {
            JSONArray ar = new JSONArray();
            for (Proof p : p_list) {
                JSONObject o = new JSONObject();
                o.put("id", p.getUser());
                o.put("alpha", ElementConversionTool.convertBytesToString(p.getAlpha()));
                o.put("beta", ElementConversionTool.convertBytesToString(p.getBeta()));
                ar.put(o);
            }
            JSONObject o = new JSONObject();
            o.put("proofs", ar);
            return o;
        } catch (JSONException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        }
    }

}
