package utils;

import java.math.BigInteger;
import java.security.Key;
import java.util.Base64;

public class StringUtil {
    public static String toString(Key key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public static String decode256(byte[] in) {
        BigInteger temp = new BigInteger(in);
        return temp.toString();
    }
}
