package crypto;

import org.bouncycastle.jcajce.provider.digest.Blake2b;
import resources.Config;
import java.security.MessageDigest;

import static crypto.Parameters.KECCAK_256;
import static crypto.Parameters.KECCAK_512;
import static util.Hex.fromHex;
import static util.Hex.getHex;

public class Hash implements Config {
    public static String sha256(String in) {
        return keccak.getHash(process(in),KECCAK_256);
    }

    public static String sha512(String in) {
        return keccak.getHash(process(in),KECCAK_512);
    }

    public static String blake256(String in) {
        byte[] input = fromHex(process(in));
        MessageDigest md = new Blake2b.Blake2b256();
        byte[] out = md.digest(input);
        return getHex(out);
    }

    public static String blake512(String in) {
        byte[] input = fromHex(process(in));
        MessageDigest md = new Blake2b.Blake2b512();
        byte[] out = md.digest(input);
        return getHex(out);
    }

    private static String process(String in) {
        return getHex(in.getBytes());
    }
}
