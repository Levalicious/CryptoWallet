package crypto;

import static utils.Base58.*;

import java.util.ArrayList;

import static crypto.Parameters.*;
import static utils.HexUtils.getHex;

public class Sha3 {
    static Keccak keccak = new Keccak();

    public static String sha256(String in) {
        return keccak.getHash(process(in),KECCAK_256);
    }

    public static String sha512(String in) {
        return keccak.getHash(process(in),KECCAK_512);
    }

    public static String addressGen(byte[] in) {
        return encode(in);
    }

    /*
    private static String getMerkleRoot(ArrayList<Transaction> transactions) {
        int count = transactions.size();
        ArrayList<String> prevLayer = new ArrayList<String>();

        for(Transaction transaction : transactions) {
            prevLayer.add(transaction.getHash());
        }

        ArrayList<String> treeLayer = prevLayer;

        while(count > 1) {
            treeLayer = new ArrayList<String>();

            for(int i = 1; i < prevLayer.size(); i++) {
                treeLayer.add(sha256(prevLayer.get(i - 1) + prevLayer.get(i)));
            }

            count = treeLayer.size();
            prevLayer = treeLayer;
        }

        String merkleRoot = (treeLayer.size() == 1) ? treeLayer.get(0) : "";
        return merkleRoot;
    }
    */

    private static String process(String in) {
        return getHex(in.getBytes());
    }
}
