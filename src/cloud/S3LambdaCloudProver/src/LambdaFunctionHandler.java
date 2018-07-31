import java.io.IOException;
import java.util.Collection;
import java.util.Map;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.util.json.JSONException;
import com.amazonaws.util.json.JSONObject;

import homomorphic_authentication_library_Java.crypto.integrity_proofs.cloud_prover.optimized.CloudProver;
import homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.challenge.data.AuditingRequest;
import homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.proof.Proof;
import homomorphic_authentication_library_Java.crypto.pairing.PairingGenerator;
import homomorphic_authentication_library_Java.crypto.pairing.ParingGeneratorFactory;
import io.S3Handler;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import json.ProofJSONConvertor;
import json.RequestParser;

public class LambdaFunctionHandler
        implements RequestHandler<Map<String, Object>, String> {
    @Override
    public String handleRequest(Map<String, Object> input, Context context) {
        System.out.println("Incoming request: '" + input.get("") + "'");
        JSONObject j;
        try {
            j = new JSONObject((String) input.get(""));
        } catch (JSONException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        }
        String params_s;
        byte[] g_b;
        try {
            params_s = S3Handler.readFile("teste-lambda", "f.param");
            g_b = S3Handler.readFileBytes("teste-lambda", "f.g");
        } catch (IOException e) {
            System.out.println(e.getMessage());
            return null;
        }
        PairingGenerator pG = ParingGeneratorFactory.getGenerator(params_s);
        pG.generate(params_s, g_b);
        Pairing pairing = pG.getPairing();
        Element g = pG.getG();
        //System.out.println("g: " + ElementConversionTool.convertElementToString(g));

        RequestParser rP = new RequestParser(pairing);
        AuditingRequest req = null;
        try {
            req = rP.convertInputToRequest(j);//*/new JSONObject(input));
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        }

        CloudProver cP = new CloudProver(pairing);
        Collection<Proof> p = cP.generateProof(req);
        ProofJSONConvertor pJ = new ProofJSONConvertor();
        return pJ.proofToJSON(p).toString();
    }
}
