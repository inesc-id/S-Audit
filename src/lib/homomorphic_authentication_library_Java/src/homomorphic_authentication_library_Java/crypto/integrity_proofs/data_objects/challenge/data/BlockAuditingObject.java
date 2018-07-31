package homomorphic_authentication_library_Java.crypto.integrity_proofs.data_objects.challenge.data;

public class BlockAuditingObject {
    private byte[][] block_content;
    private byte[][] signature;
    private int numBlocks;

    //private String[] block_id;

    public BlockAuditingObject(int numBlocks) {
        block_content = new byte[numBlocks][];
        signature = new byte[numBlocks][];
        //block_id = new String[numBlocks];
        this.numBlocks = numBlocks;
    }

    public BlockAuditingObject(byte[][] blockContent, byte[][] signature, String[] id) {
        this.block_content = blockContent;
        this.signature = signature;
        //this.block_id = id;
    }


    /*
        public BlockAuditingObject(byte[] block_content, byte[] signature, String block_id) {
            super();
            this.block_content = block_content;
            this.signature = signature;
            this.block_id = block_id;
        }
    */
    /**
     * @return the block_content
     */
    public byte[] getBlock_content(int index) {
        return block_content[index];
    }

    /**
     * @param block_content the block_content to set
     */
    public void setBlock_content(int index, byte[] block_content) {
        this.block_content[index] = block_content;
    }

    /**
     * @return the signature
     */
    public byte[] getSignature(int index) {
        return signature[index];
    }

    /**
     * @param signature the signature to set
     */
    public void setSignature(int index, byte[] signature) {
        this.signature[index] = signature;
    }

    public void setBlock(int index, byte[] block_content, byte[] signature) {
        this.setBlock_content(index, block_content);
        this.setSignature(index, signature);
    }

    public void setAllBlocks(byte[][] block_content, byte[][] signature) {
        this.block_content = block_content;
        this.signature = signature;
    }

    /**
     * @return the numBlocks
     */
    public int getNumBlocks() {
        return numBlocks;
    }


}
