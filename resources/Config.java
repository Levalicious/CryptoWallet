package resources;

import crypto.Keccak;

public interface Config {
    /* Initialize one Keccak instance for all sponge hashes */
    Keccak keccak = new Keccak();

    /* Largest allowed block size in bytes */
    long MAX_BLOCK_SIZE = 10;

    /* Min fee per byte */
    long MIN_BYTE_FEE = 1;

    /* Prefix for public addresses */
    String NETWORK_ID = "0x00";

    /* Prefix for WIF strings */
    String WIF_PREFIX = "0x80";

    /* Curve for signing */
    String curve = "secp256k1";
}
