# CryptoWallet

To generate a new wallet with a random keypair, initialize a wallet in a class with Wallet wallet = new Wallet();

To generate a wallet from a WIF, use Wallet wallet = new Wallet(*insert your WIF here as a String*);

The following methods can be called from your wallet objects:

getPublicKey()

getPublicAddress()

getPrivateKey()

getWIF()

setPrivate(String wif)

setPublic()

You can customize the network ID and the WIF prefix at the top of Wallet.java

This uses BitcoinJ's Base58 class & their AddressFormatException class, and this repo for hashing: https://github.com/romus/sha
