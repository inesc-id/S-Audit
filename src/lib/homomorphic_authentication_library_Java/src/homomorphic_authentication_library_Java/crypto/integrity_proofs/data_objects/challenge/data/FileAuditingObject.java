package homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.challenge.data;

import homomorphic_authentication_library_Java.homo_hashing.FileBlockHasher;
import homomorphic_authentication_library_Java.io.DataManipulator;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;

public class FileAuditingObject {
    String id;
    //HashMap<Integer, BlockAuditingObject> blocks;
    BlockAuditingObject blocks = null;

    Collection<Integer> indexes;
    double granularity;
    int fileSize;

    {
        this.granularity = -1;
        //this.blocks = new HashMap<Integer, BlockAuditingObject>();
        indexes = new ArrayList<>();
    }

    public FileAuditingObject(String id, int fileSize, int blockSize) {
        super();
        this.id = id;
        this.fileSize = fileSize;
        int num = DataManipulator.get_num_splits(fileSize, blockSize);
        this.blocks = new BlockAuditingObject(num);
    }

    public FileAuditingObject(String id, int fileSize, int blockSize, double granularity) {
        super();
        this.id = id;
        this.fileSize = fileSize;
        this.granularity = granularity;
        int num = FileBlockHasher.getNumBlocks(granularity, fileSize, blockSize);
        this.blocks = new BlockAuditingObject(num);
    }

    /**
     * @return the id
     */
    public String getId() {
        return id;
    }

    /**
     * @param id the id to set
     */
    public void setId(String id) {
        this.id = id;
    }


    /**
     * @param blocks the blocks to set
     */
    public void setBlocks(BlockAuditingObject blocks) {
        this.blocks = blocks;
    }

    public BlockAuditingObject getBlocks() {
        return blocks;
    }

    /**
     * @return the granularity
     */
    public double getGranularity() {
        return granularity;
    }

    /**
     * @return the fileSize
     */
    public int getFileSize() {
        return fileSize;
    }

    /**
     * @return the indexes
     */
    public Collection<Integer> getIndexes() {
        return indexes;
    }

    /**
     * @param indexes the indexes to set
     */
    public void setIndexes(Collection<Integer> indexes) {
        this.indexes = indexes;
    }

}
