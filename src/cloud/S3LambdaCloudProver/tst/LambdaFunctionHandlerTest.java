import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.junit.BeforeClass;
import org.junit.Test;

import com.amazonaws.services.lambda.runtime.Context;

/**
 * A simple test harness for locally invoking your Lambda function handler.
 */
public class LambdaFunctionHandlerTest {

    private static Map<String, Object> input;//String input;

    @BeforeClass
    public static void createInput() throws IOException {
        // TODO: set up your sample input object here.
        //input = null;
        //input = "{\"users\": [{ \"id\":\"John\", \"bucket_name\":\"teste-lambda\" , \"files\": [ {\"file_name\":\"hello.txt\" , \"bucket\" : \"teste-lambda\", \"challenge\" : \"1234\" } ] }]}";
        input = new HashMap<String, Object>();
        //String s = "{\"users\": [{ \"id\":\"Alice\", \"bucket_name\":\"teste-lambda\" , \"files\": [ {\"file_name\":\"A_1.txt\" , \"bucket\" : \"teste-lambda\", \"challenge\" : \"74\" },{\"file_name\":\"A_2.txt\" , \"bucket\" : \"teste-lambda\", \"challenge\" : \"70\" } ] }]}";
        String s =
            "{\"users\": [{ \"id\":\"Alice\", \"bucket_name\":\"teste-lambda\" , \"files\": [ {\"file_name\":\"A_3.txt\" , \"bucket\" : \"teste-lambda\",\"granularity\" : \"50.0\", \"blocks\":["/**/
                    /*+ "{\"block_index\":0,\"challenge_val\":\"1\"}"
                      + ",{\"block_index\":1,\"challenge_val\":\"1\"}"*/
                    + "]" + ",\"global_challenge\":\"83\"" + "}]}]}";
        String file = "ex.txt";
        String bucket = "eval-f";
        s = "{\"users\": [{ \"id\":\"AliceF\", \"bucket_name\":\"eval-cred\" , \"files\": [ {\"file_name\":\""
                + file + "\" , \"bucket\" : \"" + bucket
                + "\",\"granularity\" : \"100.0\", \"blocks\":["/**/
                /*+ "{\"block_index\":0,\"challenge_val\":\"1\"}"
                  + ",{\"block_index\":1,\"challenge_val\":\"1\"}"*/
                + "]" + ",\"global_challenge\":\"83\"" + "}]}]}";
        input.put("", s);
    }

    private Context createContext() {
        TestContext ctx = new TestContext();

        // TODO: customize your context here if needed.
        ctx.setFunctionName("Your Function Name");

        return ctx;
    }

    @Test
    public void testLambdaFunctionHandler() {
        LambdaFunctionHandler handler = new LambdaFunctionHandler();
        Context ctx = createContext();

        Object output = handler.handleRequest(input, ctx);

        // TODO: validate output here if needed.
        if (output != null) {
            System.out.println(output.toString());
        }
    }
}
