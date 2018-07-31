package storage_integrity_verifier.json;

import homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.challenge.input.Challenge;
import homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.challenge.input.FileBlockChallenge;
import homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.challenge.input.FileChallenge;
import homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.challenge.input.UserChallenge;

import java.util.HashMap;

import com.amazonaws.util.json.JSONArray;
import com.amazonaws.util.json.JSONException;
import com.amazonaws.util.json.JSONObject;

public class RequestParser {

    public RequestParser() {
        // TODO Auto-generated constructor stub
    }

    public HashMap<String, UserAuthenticationMetadata> convertInputToUserAuthenticationMetadata(JSONObject input) {
        try {
            HashMap<String, UserAuthenticationMetadata> map = new HashMap<>();
            JSONArray users = input.getJSONArray("users");

            for (int i = 0; i < users.length(); i++) {
                JSONObject u = users.getJSONObject(i);
                String id = u.getString("id");
                String pk = u.getString("pub_key");
                String w = u.getString("w");
                UserAuthenticationMetadata m = new UserAuthenticationMetadata(id, pk, w);
                map.put(id, m);
            }

            return map;

        } catch (JSONException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        }
    }

    public Challenge convertInputToChallenge(JSONObject input) throws JSONException {
        Challenge c = null;

        c = new Challenge();
        JSONArray users = input.getJSONArray("users");
        for (int i = 0; i < users.length(); i++) {
            JSONObject u = users.getJSONObject(i);

            String user_id = u.getString("id");

            UserChallenge u_c = new UserChallenge(user_id);
            JSONArray files = u.getJSONArray("files");

            for (int j = 0; j < files.length(); j++) {
                JSONObject f = files.getJSONObject(j);

                String file_id = f.getString("file_name");

                FileChallenge f_c = new FileChallenge(file_id);

                JSONArray blocks = f.getJSONArray("blocks");
                for (int z = 0; z < blocks.length(); z++) {
                    JSONObject b = blocks.getJSONObject(z);
                    int index = b.getInt("block_index");
                    int chal_val = b.getInt("challenge_val");
                    FileBlockChallenge b_c = new FileBlockChallenge(index, chal_val);
                    f_c.addFileBlock(b_c);
                }
                u_c.addFileChallenge(f_c);
            }
            c.addUserChallenge(user_id, u_c);
        }

        return c;
    }
}
