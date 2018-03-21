package user;

import java.security.PrivateKey;
import java.security.PublicKey;

import static util.wallet.Private.*;
import static util.wallet.Public.*;

public class Wallet {
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public Wallet() {
        newWallet();
        refreshKeyPair();
    }

    private Wallet(String wif) {
        this.privateKey = stringToPrivateKey(wif);
        refreshKeyPair();
    }

    public static Wallet importWallet(String wif) {
        Wallet wallet = new Wallet(wif);
        return wallet;
    }

    @Override
    public String toString() {
        refreshKeyPair();
        String s = "+====+ Public Address +====+\n";
        s = s + publicKeyToAddress(this.publicKey) + "\n";
        s = s + "\n";
        s = s + "+====+ WIF +====+\n";
        s = s + privateKeyToWIF(this.privateKey) + "\n";
        s = s + "\n";
        return s;
    }

    public String getKeys() {
        refreshKeyPair();
        String s = "+====+ Public Key +====+\n";
        s = s + publicKeyToString(this.publicKey) + "\n";
        s = s + "\n";
        s = s + "+====+ Private Key +====+\n";
        s = s + privateKeyToString(this.privateKey) + "\n";
        s = s + "\n";
        return s;
    }

    public String getPubAddress() {
        refreshKeyPair();
        return publicKeyToAddress(this.publicKey);
    }

    public String getPubKey() {
        refreshKeyPair();
        return publicKeyToString(this.publicKey);
    }

    public String getWIF() {
        return privateKeyToWIF(this.privateKey);
    }

    public String getPrivKey() {
        return privateKeyToString(this.privateKey);
    }

    private void refreshKeyPair() {
        this.publicKey = privateKeyToPublicKey(this.privateKey);
    }

    private void newWallet() {
        this.privateKey = generateNewPrivateKey();
    }
}