package homomorphic_authentication_library_Java.io;

import java.security.InvalidParameterException;
import java.util.Arrays;

public class DataManipulator {
    public static int get_num_splits(String message, int chunk_size) {
        int message_length = message.length();
        int num_splits = message_length / chunk_size;
        if (message_length % chunk_size > 0) {
            num_splits++;
        }
        return num_splits;
    }

    public static int get_num_splits(int length, int chunk_size) {

        int num_splits = length / chunk_size;
        if (length % chunk_size > 0) {
            num_splits++;
        }
        return num_splits;
    }

    public static byte[][] split_message(String message, int chunk_size) {
        return split_message(message.getBytes(), chunk_size);
    }

    public static byte[][] split_message(byte[] bytes_mk, int chunk_size) {
        int message_length = bytes_mk.length;
        int num_splits = message_length / chunk_size;

        boolean hasRemainderChunk = message_length % chunk_size > 0;
        if (hasRemainderChunk)
            num_splits++;
        byte[][] split_message = new byte[num_splits][];
        int i;
        for (i = 0; i < num_splits - 1; i++) {
            byte[] bytes_mk_i = Arrays.copyOfRange(bytes_mk, i * chunk_size, (i + 1) * chunk_size);
            split_message[i] = bytes_mk_i;
        }
        int last_chunk;
        if (hasRemainderChunk) {
            last_chunk = message_length % chunk_size;
        } else {
            last_chunk = chunk_size;
        }
        split_message[i] = Arrays
                .copyOfRange(bytes_mk, i * chunk_size, i * chunk_size + last_chunk);

        return split_message;
    }



    public static byte[] get_block(byte[] v, int chunk_size, int block_index) {
        int v_length = v.length;
        int num_splits = v_length / chunk_size;
        boolean hasRemainderChunk = v_length % chunk_size > 0;
        if (hasRemainderChunk)
            num_splits++;

        if (block_index < 0 || block_index >= num_splits) {
            throw new InvalidParameterException(
                    "block_index must be within the range of 0 to the size of the vector.");
        } else if (block_index < num_splits - 1) {
            return Arrays.copyOfRange(v, block_index * chunk_size, block_index * chunk_size
                    + chunk_size);
        } else {
            int last_chunk_size = v_length % chunk_size;
            return Arrays.copyOfRange(v, block_index * chunk_size, block_index * chunk_size
                    + last_chunk_size);
        }
    }

    public static byte[] get_aggregated_message_block(byte[] v,
                                                      int chunk_size,
                                                      int block_index,
                                                      int granularity) {
        int v_length = v.length;
        int num_splits = v_length / (chunk_size * granularity);
        boolean hasRemainderChunk = v_length % (chunk_size * granularity) > 0;
        if (hasRemainderChunk)
            num_splits++;

        if (block_index < 0 || block_index >= num_splits) {
            throw new InvalidParameterException(
                    "block_index must be within the range of 0 to the size of the vector.");
        } else if (block_index < num_splits - 1) {
            return Arrays.copyOfRange(v, block_index * chunk_size, block_index * chunk_size
                    + chunk_size);
        } else {
            int last_chunk_size = v_length % chunk_size;
            return Arrays.copyOfRange(v, block_index * chunk_size, block_index * chunk_size
                    + last_chunk_size);
        }
    }

    public static byte[] aggregateDataBlocks(int chunk_size, byte[]... blocks) {
        int num_splits = blocks.length;
        int last_chunk_size = blocks[num_splits - 1].length;
        int size_last_chunk = last_chunk_size % chunk_size;
        int length_ag_sig = 0;
        if (num_splits > 0) {
            length_ag_sig = chunk_size * (num_splits - 1);
        } else
            length_ag_sig = 0;
        if (size_last_chunk == 0) {
            length_ag_sig = length_ag_sig + chunk_size;
        } else {
            length_ag_sig = length_ag_sig + size_last_chunk;
        }

        byte[] sig = new byte[length_ag_sig];
        int i;
        for (i = 0; i < num_splits - 1; i++) {
            System.arraycopy(blocks[i], 0, sig, i * chunk_size, chunk_size);
        }
        if (size_last_chunk == 0) {
            System.arraycopy(blocks[i], 0, sig, i * chunk_size, chunk_size);
        } else
            System.arraycopy(blocks[i], 0, sig, i * chunk_size, size_last_chunk);
        return sig;
    }

}
