package wallet;

import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;

import static utils.Base58.*;
import static utils.HexUtils.*;
import static utils.StringUtil.*;
import static crypto.Sha3.*;

import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.*;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;

public class Wallet {
    private PrivateKey privateKey;
    private PublicKey publicKey;

    private final String NETWORK_ID = "0x00";
    private final String WIF_PREFIX = "0x80";

    public Wallet() {
        Security.addProvider(new BouncyCastleProvider());
        generateKeyPair();
    }

    public Wallet(String wif) throws GeneralSecurityException {
        setPrivate(wif);
        setPublic();
        //setPublic(this.privateKey);
    }

    private void generateKeyPair(){
        try{
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA","BC");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256k1");

            keyGen.initialize(ecSpec, random);

            KeyPair keyPair = keyGen.generateKeyPair();

            privateKey = keyPair.getPrivate();
            publicKey = keyPair.getPublic();
        }catch(Exception e) {
            System.out.println("Key generation failed.");
            throw new RuntimeException(e);
        }
    }

    public String getPublicKey() throws GeneralSecurityException{
        return getHex(publicKey.getEncoded());
    }

    public String getPublicAddress() throws GeneralSecurityException{
        String temp = getHex(((ECPublicKey)publicKey).getW().getAffineX().toByteArray()) + getHex(((ECPublicKey)publicKey).getW().getAffineY().toByteArray());
        temp = "0x04" + temp;

        byte[] r = fromHex(sha256(decode256(fromHex(temp))));

        RIPEMD160Digest d = new RIPEMD160Digest();
        d.update(r,0,r.length);
        byte[] o = new byte[d.getDigestSize()];
        d.doFinal(o,0);

        temp = NETWORK_ID + getHex(o);
        temp = temp + sha256(decode256(fromHex(sha256(decode256(fromHex(temp))))));

        return encode(fromHex(temp));
    }

    public String getPrivateKey() {
        return getHex(privateKey.getEncoded());
    }

    public String toString() {
        return publicKey.toString();
    }

    public String getWIF() {
        String tempKey = getHex(privateKey.getEncoded());
        tempKey = WIF_PREFIX + tempKey;
        String keyHash = sha256(decode256(fromHex(sha256(decode256(fromHex(tempKey))))));
        keyHash = keyHash.substring(0,8);
        String wif = tempKey + keyHash;
        return encode(fromHex(wif));
    }

    public void setPrivate(String wif) throws GeneralSecurityException{
        String temp = getHex(decode(wif));
        if(temp.startsWith("0")) {
            temp = temp.substring(1);
        }
        temp = temp.substring(2, temp.length() - 8);

        byte[] pkcs8key = fromHex(temp);

        Security.addProvider(new BouncyCastleProvider());
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pkcs8key);
        KeyFactory factory = KeyFactory.getInstance("ECDSA","BC");
        this.privateKey = factory.generatePrivate(spec);
    }

    public void setPublic() throws GeneralSecurityException {
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");

        ECPoint Q = ecSpec.getG().multiply(((org.bouncycastle.jce.interfaces.ECPrivateKey) this.privateKey).getD());
        byte[] publicDerBytes = Q.getEncoded(false);

        ECPoint point = ecSpec.getCurve().decodePoint(publicDerBytes);
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, ecSpec);
        PublicKey publicKeyGenerated = keyFactory.generatePublic(pubSpec);
        this.publicKey = publicKeyGenerated;
    }
}
