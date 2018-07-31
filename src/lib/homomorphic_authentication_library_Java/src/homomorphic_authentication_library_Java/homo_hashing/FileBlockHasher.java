package homomorphic_authentication_library_Java.homo_hashing;

import java.security.InvalidParameterException;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.GeneralDigest;
import org.bouncycastle.crypto.digests.SHA256Digest;

import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import homomorphic_authentication_library_Java.io.DataManipulator;

public class FileBlockHasher {


    public static byte[][] homomorphicHashFileBlocks(byte[] content, int granularity, Field f) {
        byte[][] message = DataManipulator.split_message(content, f.getLengthInBytes()
                * granularity);

        for (int i = 0; i < message.length; i++) {
            HomomorphicHasher h = new HomomorphicHasher(f);
            h.doFinal(message[i], 1);
            message[i] = h.digest();
        }

        return message;
    }

    public static byte[] hashFileBlocks(byte[] content,
                                        int granularity,
                                        int blockSize,
                                        GeneralDigest digest) {
        byte[][] message = DataManipulator.split_message(content, blockSize * granularity);

        for (int i = 0; i < message.length; i++) {
            int digestSize = digest.getDigestSize();
            byte[] hash = new byte[digestSize];
            digest.reset();
            digest.update(message[i], 0, message[i].length);
            digest.doFinal(hash, 0);
            message[i] = hash;
        }

        return DataManipulator.aggregateDataBlocks(message[0].length, message);
    }

    public static int getNumBlocks(double percentage, int fileLength, int blockSize) {
        if (percentage < 0 || percentage > 100) {
            throw new InvalidParameterException();
        }

        int num_blocks = fileLength / blockSize;
        if (fileLength % blockSize > 0) {
            num_blocks++;
        }

        return num_blocks;
    }

    public static int calculateGranularity(double percentage, int fileLength, int blockSize) {
        if (percentage < 0 || percentage > 100) {
            throw new InvalidParameterException();
        }

        int num_blocks = fileLength / blockSize;
        if (fileLength % blockSize > 0) {
            num_blocks++;
        }

        return (int) Math.ceil(num_blocks * percentage / 100);
    }
}
