package homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.challenge.input;

import java.util.ArrayList;
import java.util.Collection;

import sun.security.provider.PolicyParser.GrantEntry;

public class FileChallenge {

    private final Collection<FileBlockChallenge> file_blocks;
    private final String id;
    private double granularity = -1;
    private int globalChallenge;

    public FileChallenge(String id, Collection<FileBlockChallenge> file_blocks) {
        this.id = id;
        this.file_blocks = file_blocks;
    }

    public FileChallenge(String id,
                         Collection<FileBlockChallenge> file_blocks,
                         double granularity) {
        this(id, file_blocks);
        this.granularity = granularity;
    }

    public FileChallenge(String id) {
        this(id, new ArrayList<FileBlockChallenge>());
    }

    public FileChallenge(String id, double granularity) {
        this(id, new ArrayList<FileBlockChallenge>(), granularity);
    }

    public FileChallenge(String id,
                         Collection<FileBlockChallenge> file_blocks,
                         int globalChallenge) {
        this.id = id;
        this.file_blocks = file_blocks;
        this.globalChallenge = globalChallenge;
    }

    public FileChallenge(String id,
                         Collection<FileBlockChallenge> file_blocks,
                         double granularity,
                         int globalChallenge) {
        this(id, file_blocks, globalChallenge);
        this.granularity = granularity;
    }

    public FileChallenge(String id, int globalChallenge) {
        this(id, new ArrayList<FileBlockChallenge>(), globalChallenge);
    }

    public FileChallenge(String id, double granularity, int globalChallenge) {
        this(id, new ArrayList<FileBlockChallenge>(), granularity, globalChallenge);
    }

    /**
     * @return the file_blocks
     */
    public Collection<FileBlockChallenge> getFile_blocks() {
        return file_blocks;
    }

    /**
     * @return the id
     */
    public String getId() {
        return id;
    }

    public void addFileBlock(int block_index, int challenge_value) {
        this.addFileBlock(new FileBlockChallenge(block_index, challenge_value));
    }

    public void addFileBlock(FileBlockChallenge f_b) {
        this.file_blocks.add(f_b);
    }

    /**
     * @return the granularity
     */
    public double getGranularity() {
        return granularity;
    }

    /**
     * @param granularity the granularity to set
     */
    public void setGranularity(double granularity) {
        this.granularity = granularity;
    }

    /**
     * @return the globalChallenge
     */
    public int getGlobalChallenge() {
        return globalChallenge;
    }

    /**
     * @param globalChallenge the globalChallenge to set
     */
    public void setGlobalChallenge(int globalChallenge) {
        this.globalChallenge = globalChallenge;
    }



}
