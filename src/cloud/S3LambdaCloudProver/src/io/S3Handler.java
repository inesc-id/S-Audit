package io;

import java.io.IOException;
import java.io.InputStream;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.model.GetObjectRequest;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.s3.model.S3ObjectInputStream;
import com.amazonaws.util.IOUtils;

public class S3Handler {

    private static AmazonS3 s3Client = new AmazonS3Client();

    public S3Handler() {
    }

    public static String readFile(String bucket, String key) {
        try {
            //System.out.println("Downloading an object");
            S3Object s3object = s3Client.getObject(new GetObjectRequest(bucket, key));
            //System.out.println("Content-Type: " + s3object.getObjectMetadata().getContentType());
            return dumpStream(s3object.getObjectContent());
            /*
                        // Get a range of bytes from an object.

                        GetObjectRequest rangeObjectRequest = new GetObjectRequest("teste-lambda", "teste.txt");
                        rangeObjectRequest.setRange(0, 10);
                        S3Object objectPortion = s3Client.getObject(rangeObjectRequest);

                        System.out.println("Printing bytes retrieved.");
                        return dumpStream(objectPortion.getObjectContent());*/


        } catch (AmazonServiceException ase) {
            System.out
                    .println("Caught an AmazonServiceException, which"
                            + " means your request made it "
                            + "to Amazon S3, but was rejected with an error response"
                            + " for some reason.");
            System.out.println("Error Message:    " + ase.getMessage());
            System.out.println("HTTP Status Code: " + ase.getStatusCode());
            System.out.println("AWS Error Code:   " + ase.getErrorCode());
            System.out.println("Error Type:       " + ase.getErrorType());
            System.out.println("Request ID:       " + ase.getRequestId());
            return ase.getMessage();
        } catch (Exception ace) {
            System.out.println("Caught an AmazonClientException, which means"
                    + " the client encountered " + "an internal error while trying to "
                    + "communicate with S3, " + "such as not being able to access the network.");
            System.out.println("Error Message: " + ace.getMessage());
            return ace.getMessage();
        }
    }

    private static String dumpStream(S3ObjectInputStream objectContent) throws IOException {
        return IOUtils.toString(objectContent);
    }

    public static byte[] readFileBytes(String bucket, String key) throws IOException {
        //System.out.println("Downloading an object");
        S3Object s3object = s3Client.getObject(new GetObjectRequest(bucket, key));
        //System.out.println("Content-Type: " + s3object.getObjectMetadata().getContentType());

        InputStream is = s3object.getObjectContent();
        return IOUtils.toByteArray(is);
    }
}
