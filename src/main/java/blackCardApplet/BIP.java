package blackCardApplet;

import javacard.framework.*;
import javacard.security.*;

class BIP {

    private static final byte BITCOIN_SEED[] = { 'B', 'i', 't', 'c', 'o', 'i', 'n', ' ', 's', 'e', 'e', 'd' };

    public static final short BITCOIN = 0;
    public static final short TESTNET = 1;
    public static final short ETHEREUM = 60;

    public static final byte ALG_EC_SVDP_DH_PLAIN_XY = (byte) 6;// Not defined until JC 3.0.5

    private Signature hmacSignature;
    private HMACKey hmacMasterKey;
    private HMACKey hmacDerivedKey;
    private KeyAgreement ecMultiplyHelper;
    private ECPrivateKey ecPrivateKeyTemp;

    public BIP() {
        hmacSignature = Signature.getInstance(Signature.ALG_HMAC_SHA_512, false);
        hmacMasterKey = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC, KeyBuilder.LENGTH_HMAC_SHA_512_BLOCK_128,
                false);
        hmacDerivedKey = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC, KeyBuilder.LENGTH_HMAC_SHA_512_BLOCK_128,
                false);
        ecMultiplyHelper = KeyAgreement.getInstance(ALG_EC_SVDP_DH_PLAIN_XY, false);
        ecPrivateKeyTemp = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE,
                KeyBuilder.LENGTH_EC_FP_256, false);
        Secp256k1.setCommonCurveParameters(ecPrivateKeyTemp);
    }

    public boolean bip32GenerateMasterKey(byte[] seed, short seedOffset, short seedLength, short coin, byte[] kcPar,
            short kcParOffset) {
        // HMAC-SHA512(key="Bitcoin seed", data=mseed) => iL|iR
        if (coin == BITCOIN) {
            hmacMasterKey.setKey(BITCOIN_SEED, (short) 0, (short) BITCOIN_SEED.length);
        } else {
            return false;
        }
        hmacSignature.init(hmacMasterKey, Signature.MODE_SIGN);
        hmacSignature.sign(seed, seedOffset, seedLength, kcPar, kcParOffset);
        // if iL=0 or >=n => invalid
        if ((kcPar[kcParOffset] == (byte) 0)
                || MathMod256.ucmp(kcPar, kcParOffset, Secp256k1.SECP256K1_R, (short) 0) >= (short) 0) {
            return false;
        }
        return true;
    }

    public short ec256PrivateKeyToPublicKey(byte[] privateKey, short privateKeyOffset, byte[] publicKey65,
            short publicKeyOffset, boolean compressed) {
        // Generate Public Key from given Private Key using the Key Agreement API
        ecPrivateKeyTemp.setS(privateKey, privateKeyOffset, (short) 32);
        ecMultiplyHelper.init(ecPrivateKeyTemp);
        short publicKeyLength = ecMultiplyHelper.generateSecret(Secp256k1.SECP256K1_G, (short) 0, (short) 65,
                publicKey65, publicKeyOffset);
        if (compressed) {
            if ((publicKey65[publicKeyOffset + publicKeyLength - 1] & 0x01) == 0x01) {// Y last digit is odd
                publicKey65[publicKeyOffset] = 0x03;
            } else {// Y last digit is even
                publicKey65[publicKeyOffset] = 0x02;
            }
            publicKeyLength = 33;
        }
        return publicKeyLength;
    }

    public boolean bip32DerivePrivateKey(byte[] kcPar64, short kcParOffset, short i, boolean hardenedKey,
            byte[] kcChi64, short kcChiOffset, byte[] scratchBuffer104, short scratchOffset) {
        // CKDpriv
        if (hardenedKey) {
            // 00|kPar|i : [37B]
            scratchBuffer104[scratchOffset] = (byte) 0x00;
            Util.arrayCopyNonAtomic(kcPar64, kcParOffset, scratchBuffer104, (short) (scratchOffset + 1), (short) 32);
            // Util.arrayCopyNonAtomic(i, iOffset, scratchBuffer, (short) 33, (short) 4);
            scratchBuffer104[scratchOffset + 33] = (byte) 0x80;// i = i + 2^31
            scratchBuffer104[scratchOffset + 34] = (byte) 0x00;
            Util.setShort(scratchBuffer104, (short) (scratchOffset + 35), i);
        } else {// normal key
            // pointX(kPar)|i : [37B]
            ec256PrivateKeyToPublicKey(kcPar64, kcParOffset, scratchBuffer104, scratchOffset, true);
            // Util.arrayCopyNonAtomic(i, iOffset, scratchBuffer, (short) 65, (short) 4);
            scratchBuffer104[scratchOffset + 33] = (byte) 0x00;
            scratchBuffer104[scratchOffset + 34] = (byte) 0x00;
            Util.setShort(scratchBuffer104, (short) (scratchOffset + 35), i);
        }

        // HMAC-SHA512(key=cPar, data=input) => iL|iR
        short iL_index = (short) (scratchOffset + 40);
        hmacDerivedKey.setKey(kcPar64, (short) 32, (short) 32);
        hmacSignature.init(hmacDerivedKey, Signature.MODE_SIGN);
        hmacSignature.sign(scratchBuffer104, (short) (scratchOffset + 0), (short) 37, scratchBuffer104, iL_index);

        // if iL>=n => invalid
        if (MathMod256.ucmp(scratchBuffer104, iL_index, Secp256k1.SECP256K1_R, (short) 0) >= (short) 0) {
            return false;
        }

        // ki = iL + kPar mod n
        MathMod256.addm(scratchBuffer104, iL_index, scratchBuffer104, iL_index, kcPar64, kcParOffset,
                Secp256k1.SECP256K1_R, (short) 0);

        // if ki=0 => invalid
        if (scratchBuffer104[iL_index] == 0x00) {
            return false;
        }

        Util.arrayCopyNonAtomic(scratchBuffer104, iL_index, kcChi64, kcChiOffset, (short) 64);
        return true;
    }

    public boolean bip44DerivePath(byte[] masterSeed, short masterSeedOffset, short masterSeedLength, byte[] keyPath,
            short keyPathOffset, byte[] privateKey32, short privateKeyOffset, short publicKeysRange, byte[] publicKeys,
            short publicKeysOffset, byte[] scratchBuffer232, short scratchOffset) {

        // m[1]/44'[1]/coin'[1]/account'[1]/change[1]/address_index[2]

        if (publicKeysRange < 1) {
            return false;
        }

        if (keyPath[keyPathOffset + 2] != BITCOIN) {
            return false;
        }
        // m
        if ((keyPath[keyPathOffset + 0] != 'm') || !bip32GenerateMasterKey(masterSeed, masterSeedOffset,
                masterSeedLength, keyPath[keyPathOffset + 2], scratchBuffer232, scratchOffset)) {
            return false;
        }
        // purpose'
        if ((keyPath[keyPathOffset + 1] != 44)
                || !bip32DerivePrivateKey(scratchBuffer232, scratchOffset, keyPath[keyPathOffset + 1], true,
                        scratchBuffer232, scratchOffset, scratchBuffer232, (short) (scratchOffset + 64))) {
            return false;
        }
        // coin'
        if (!bip32DerivePrivateKey(scratchBuffer232, scratchOffset, keyPath[keyPathOffset + 2], true, scratchBuffer232,
                scratchOffset, scratchBuffer232, (short) (scratchOffset + 64))) {
            return false;
        }
        // account'
        if ((keyPath[keyPathOffset + 3] > 255)
                || !bip32DerivePrivateKey(scratchBuffer232, scratchOffset, keyPath[keyPathOffset + 3], true,
                        scratchBuffer232, scratchOffset, scratchBuffer232, (short) (scratchOffset + 64))) {
            return false;
        }
        // change
        if ((keyPath[keyPathOffset + 4] > 2)
                || !bip32DerivePrivateKey(scratchBuffer232, scratchOffset, keyPath[keyPathOffset + 4], false,
                        scratchBuffer232, scratchOffset, scratchBuffer232, (short) (scratchOffset + 64))) {
            return false;
        }
        // address_index
        short address_index = Util.makeShort(keyPath[keyPathOffset + 5], keyPath[keyPathOffset + 6]);
        for (short i = 0; i < publicKeysRange; i++) {
            if (!bip32DerivePrivateKey(scratchBuffer232, scratchOffset, (short) (address_index + i), false,
                    scratchBuffer232, (short) (scratchOffset + 64), scratchBuffer232, (short) (scratchOffset + 128))) {
                return false;
            }
            Util.arrayCopyNonAtomic(scratchBuffer232, (short) (scratchOffset + 64), privateKey32, privateKeyOffset,
                    (short) 32);
            ec256PrivateKeyToPublicKey(privateKey32, privateKeyOffset, publicKeys,
                    (short) (publicKeysOffset + (short) (i * 65)), false);
        }
        return true;
    }
}