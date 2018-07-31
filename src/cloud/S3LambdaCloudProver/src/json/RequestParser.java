package json;

import homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.challenge.data.AuditingData;
import homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.challenge.data.AuditingRequest;
import homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.challenge.data.BlockAuditingObject;
import homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.challenge.data.FileAuditingObject;
import homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.challenge.data.UserAuditingObject;
import homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.challenge.input.Challenge;
import homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.challenge.input.FileBlockChallenge;
import homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.challenge.input.UserChallenge;
import homomorphic_authentication_library_Java.homo_hashing.FileBlockHasher;
import homomorphic_authentication_library_Java.io.DataManipulator;
import homomorphic_authentication_library_Java.io.ElementConversionTool;
import io.S3Handler;
import it.unisa.dia.gas.jpbc.Pairing;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;

import com.amazonaws.util.json.JSONArray;
import com.amazonaws.util.json.JSONException;
import com.amazonaws.util.json.JSONObject;

public class RequestParser {
    private Pairing p;

    public RequestParser(Pairing pairing) {
        // TODO Auto-generated constructor stub
        this.p = pairing;
    }

    private Challenge convertInputToChallenge(JSONObject input) throws JSONException {
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
                String bucket = f.getString("bucket");
                //double granularity = new Double(f.getString("granularity"));

                JSONArray blocks = f.getJSONArray("blocks");
                S3FileChallenge f_c;
                if (blocks.length() == 0) {
                    int chal_val = f.getInt("global_challenge");
                    f_c = new S3FileChallenge(file_id, bucket, chal_val);
                } else {
                    f_c = new S3FileChallenge(file_id, bucket);
                    for (int z = 0; z < blocks.length(); z++) {
                        JSONObject b = blocks.getJSONObject(z);
                        int index = b.getInt("block_index");
                        int chal_val = b.getInt("challenge_val");
                        FileBlockChallenge b_c = new FileBlockChallenge(index, chal_val);
                        f_c.addFileBlock(b_c);
                    }
                }
                u_c.addFileChallenge(f_c);
            }
            c.addUserChallenge(user_id, u_c);
        }

        return c;
    }

    private AuditingData readS3DataFromInput(JSONObject input) throws JSONException, IOException {
        AuditingData data = new AuditingData();

        JSONArray users = input.getJSONArray("users");
        for (int i = 0; i < users.length(); i++) {
            JSONObject u = users.getJSONObject(i);

            String user_id = u.getString("id");

            UserAuditingObject u_c = new UserAuditingObject(user_id);
            u_c.setW(ElementConversionTool.convertBytesToElement(
                    S3Handler.readFileBytes("teste-lambda", user_id + ".w"), this.p.getG1()));

            JSONArray files = u.getJSONArray("files");

            for (int j = 0; j < files.length(); j++) {
                JSONObject f = files.getJSONObject(j);

                String file_id = f.getString("file_name");
                String f_bucket = f.getString("bucket");

                String file_content = S3Handler.readFile(f_bucket, file_id);

                byte[][] file_content_b =
                    DataManipulator.split_message(file_content, this.p.getZr().getLengthInBytes());

                byte[] sig_content = S3Handler.readFileBytes(f_bucket, file_id + ".sig");
                byte[][] sig_content_b = DataManipulator.split_message(sig_content,
                        this.p.getG1().getLengthInBytes() / 2 + 1);

                S3FileAuditingObject f_c = new S3FileAuditingObject(file_id, f_bucket,
                        file_content.length(), p.getZr().getLengthInBytes());

                JSONArray blocks = f.getJSONArray("blocks");
                BlockAuditingObject b_1_1 = f_c.getBlocks();
                if (blocks.length() == 0) {
                    b_1_1.setAllBlocks(file_content_b, sig_content_b);
                } else {
                    Collection<Integer> indexes = new ArrayList<Integer>();
                    for (int z = 0; z < blocks.length(); z++) {
                        JSONObject b = blocks.getJSONObject(z);
                        int index = b.getInt("block_index");
                        String b_id = file_id + index;
                        indexes.add(index);
                        byte[] signature = sig_content_b[z];
                        byte[] block_content = file_content_b[z];
                        b_1_1.setBlock(index, block_content, signature);
                    }
                }
                u_c.addFile(file_id, f_c);
            }
            data.addUser(user_id, u_c);
        }

        return data;
    }

    public AuditingRequest convertInputToRequest(JSONObject input) throws IOException {
        Challenge challenge = null;
        AuditingData data = null;
        try {
            challenge = this.convertInputToChallenge(input);
            data = this.readS3DataFromInput(input);
            return new AuditingRequest(challenge, data);
        } catch (JSONException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
            return null;
        }
    }
}
