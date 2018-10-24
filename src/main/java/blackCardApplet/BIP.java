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
    private HMACKey hmacKey;
    private KeyAgreement ecMultiplyHelper;
    private ECPrivateKey ecPrivateKeyTemp;

    public BIP() {
        hmacSignature = Signature.getInstance(Signature.ALG_HMAC_SHA_512, false);
        hmacKey = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC, KeyBuilder.LENGTH_HMAC_SHA_512_BLOCK_128, false);
        ecMultiplyHelper = KeyAgreement.getInstance(ALG_EC_SVDP_DH_PLAIN_XY, false);
        ecPrivateKeyTemp = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE,
                KeyBuilder.LENGTH_EC_FP_256, false);
        Secp256k1.setCommonCurveParameters(ecPrivateKeyTemp);
    }

    public boolean bip32GenerateMasterKey(byte[] seed, short seedOffset, short seedLength, short coin, byte[] kcPar,
            short kcParOffset) {
        // HMAC-SHA512(key="Bitcoin seed", data=mseed) => iL|iR
        if (coin == BITCOIN) {
            hmacKey.setKey(BITCOIN_SEED, (short) 0, (short) BITCOIN_SEED.length);
        } else {
            return false;
        }
        hmacSignature.init(hmacKey, Signature.MODE_SIGN);
        hmacSignature.sign(seed, seedOffset, seedLength, kcPar, kcParOffset);
        // if iL=0 or >=n => invalid
        if ((kcPar[kcParOffset] == (byte) 0)
                || MathMod256.ucmp(kcPar, kcParOffset, Secp256k1.SECP256K1_R, (short) 0) >= (short) 0) {
            return false;
        }
        return true;
    }

    public short ec256PrivateKeyToPublicKey(byte[] privateKey, short privateKeyOffset, byte[] publicKey,
            short publicKeyOffset) {
        // Generate Public Key from given Private Key using the Key Agreement API
        ecPrivateKeyTemp.setS(privateKey, privateKeyOffset, (short) 32);
        ecMultiplyHelper.init(ecPrivateKeyTemp);
        short publicKeyLength = ecMultiplyHelper.generateSecret(Secp256k1.SECP256K1_G, (short) 0, (short) 65, publicKey,
                publicKeyOffset);
        return publicKeyLength;
    }

    public boolean bip32DerivePrivateKey(byte[] kcPar, short kcParOffset, short i, boolean hardenedKey, byte[] kcChi,
            short kcChiOffset, byte[] scratchBuffer, short scratchOffset) {
        // CKDpriv
        short inputLen = 0;
        if (hardenedKey) {
            // 00|kPar|i : [37B]
            scratchBuffer[scratchOffset] = (byte) 0x00;
            Util.arrayCopyNonAtomic(kcPar, kcParOffset, scratchBuffer, (short) (scratchOffset + 1), (short) 32);
            // Util.arrayCopyNonAtomic(i, iOffset, scratchBuffer, (short) 33, (short) 4);
            scratchBuffer[scratchOffset + 33] = (byte) 0x80;// i = i + 2^31
            scratchBuffer[scratchOffset + 34] = (byte) 0x00;
            Util.setShort(scratchBuffer, (short) (scratchOffset + 35), i);
            inputLen = 37;
        } else {// normal key
            // point(kPar)|i : [69B]
            short pubKeyLen = ec256PrivateKeyToPublicKey(kcPar, kcParOffset, scratchBuffer, scratchOffset);
            // Util.arrayCopyNonAtomic(i, iOffset, scratchBuffer, (short) 65, (short) 4);
            scratchBuffer[scratchOffset + 65] = (byte) 0x00;
            scratchBuffer[scratchOffset + 66] = (byte) 0x00;
            Util.setShort(scratchBuffer, (short) (scratchOffset + 67), i);
            inputLen = 69;
        }

        // HMAC-SHA512(key=cPar, data=input) => iL|iR
        short iL_index = (short) (scratchOffset + 70);
        hmacKey.setKey(kcPar, (short) 32, (short) 32);
        hmacSignature.init(hmacKey, Signature.MODE_SIGN);
        hmacSignature.sign(scratchBuffer, (short) (scratchOffset + 0), inputLen, scratchBuffer, iL_index);

        // if iL>=n => invalid
        if (MathMod256.ucmp(scratchBuffer, iL_index, Secp256k1.SECP256K1_R, (short) 0) >= (short) 0) {
            return false;
        }

        // ki = iL + kPar mod n
        MathMod256.addm(scratchBuffer, iL_index, scratchBuffer, iL_index, kcPar, kcParOffset, Secp256k1.SECP256K1_R,
                (short) 0);

        // if ki=0 => invalid
        if (scratchBuffer[iL_index] == 0x00) {
            return false;
        }

        Util.arrayCopyNonAtomic(scratchBuffer, iL_index, kcChi, kcChiOffset, (short) 64);
        return true;
    }

    public boolean bip44DerivePath(byte[] masterSeed, short masterSeedOffset, short masterSeedLength, byte[] keyPath,
            byte[] privateKey, short privateKeyOffset, short publicKeysRange, byte[] publicKeys, short publicKeysOffset,
            byte[] scratchBuffer, short scratchOffset) {

        if (keyPath[2] != BITCOIN) {
            return false;
        }
        // m
        if ((keyPath[0] != 'm') || !bip32GenerateMasterKey(masterSeed, masterSeedOffset, masterSeedLength, keyPath[2],
                scratchBuffer, scratchOffset)) {
            return false;
        }
        // purpose'
        if ((keyPath[1] != 44) || !bip32DerivePrivateKey(scratchBuffer, scratchOffset, keyPath[1], true, scratchBuffer,
                scratchOffset, scratchBuffer, (short) (scratchOffset + 64))) {
            return false;
        }
        // coin'
        if (!bip32DerivePrivateKey(scratchBuffer, scratchOffset, keyPath[2], true, scratchBuffer, scratchOffset,
                scratchBuffer, (short) (scratchOffset + 64))) {
            return false;
        }
        // account'
        if ((keyPath[3] > 255) || !bip32DerivePrivateKey(scratchBuffer, scratchOffset, keyPath[3], true, scratchBuffer,
                scratchOffset, scratchBuffer, (short) (scratchOffset + 64))) {
            return false;
        }
        // change
        if ((keyPath[4] > 2) || !bip32DerivePrivateKey(scratchBuffer, scratchOffset, keyPath[4], false, scratchBuffer,
                scratchOffset, scratchBuffer, (short) (scratchOffset + 64))) {
            return false;
        }
        // address_index
        short address_index = Util.makeShort(keyPath[5], keyPath[6]);
        for (short i = 0; i < publicKeysRange; i++) {
            if (!bip32DerivePrivateKey(scratchBuffer, scratchOffset, (short) (address_index + i), false, privateKey,
                    privateKeyOffset, scratchBuffer, (short) (scratchOffset + 64))) {
                return false;
            }
            if (publicKeys != null) {
                ec256PrivateKeyToPublicKey(privateKey, privateKeyOffset, publicKeys,
                        (short) (publicKeysOffset + (short) (i * 65)));
            }
        }
        return true;
    }
}