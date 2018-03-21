package util;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import static util.Base58.decode;
import static util.Base58.encode;
import static util.Hex.fromHex;
import static util.Hex.getHex;
import static util.wallet.Private.stringToPrivateKey;
import static util.wallet.Public.stringToPublicKey;

public class Sign {
    public static String signString(String WIF, String in) {
        PrivateKey privateKey = stringToPrivateKey(WIF);
        return signData(privateKey, in);
    }

    public static String signString(PrivateKey privateKey, String in) {
        return signData(privateKey, in);
    }

    public static boolean verifySig(String pubKey, String data, String sig) {
        PublicKey publicKey = stringToPublicKey(pubKey);

        try {
            Signature verify = Signature.getInstance("ECDSA","BC");
            verify.initVerify(publicKey);
            verify.update(data.getBytes());
            return verify.verify(fromHex(getHex(decode(sig))));
        }
        catch (Exception e) {
            System.out.println("Signature validation failed");
            throw new RuntimeException(e);
        }
    }

    private static String signData(PrivateKey privateKey, String in) {
        Signature sig;
        byte[] output = new byte[0];
        try {
            sig = Signature.getInstance("ECDSA","BC");
            sig.initSign(privateKey);
            byte[] strByte = in.getBytes();
            sig.update(strByte);
            byte[] sigFinal = sig.sign();
            output = sigFinal;
        }
        catch (Exception e) {
            System.out.println("Message signing failed.");
            throw new RuntimeException(e);
        }
        return encode(fromHex(getHex(output)));
    }
}
