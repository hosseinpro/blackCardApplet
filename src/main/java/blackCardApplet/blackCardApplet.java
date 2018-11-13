package blackCardApplet;

import javacard.framework.*;
import javacard.security.*;
import javacardx.apdu.ExtendedLength;
import javacardx.crypto.Cipher;

public class blackCardApplet extends Applet implements ISO7816, ExtendedLength {
    public static final byte[] AID = { (byte) 0xFF, (byte) 0xBC, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01 };

    private static final byte PIN_SIZE = 4;
    private static final byte PUK_SIZE = 8;
    private static final byte SERIALNUMBER_SIZE = 8;
    private static final short SW_PIN_INCORRECT_TRIES_LEFT = (short) 0x63C0;
    private static final short LABEL_SIZE_MAX = 16;
    private static final short HASH_SIZE = 32;
    private static final short MSEED_SIZE = 64;

    private static OwnerPIN pin;
    private static OwnerPIN puk;
    private static OwnerPIN yesCode;
    private static RandomData randomData;
    private static boolean isPersonalized;

    private static byte[] serialNumber;
    private byte[] tempSerialNumber;
    private static final byte version[] = { 'B', ' ', '1', '.', '0' };
    private static final byte defaultLabel[] = { 'B', 'l', 'a', 'c', 'k', 'C', 'a', 'r', 'd' };
    private static byte[] label;
    private static short labelLength;
    private static final byte defaultPIN[] = { '1', '2', '3', '4' };
    private byte P2PKH[] = { 0x19, 0x76, (byte) 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, (byte) 0x88, (byte) 0xac };

    private static byte[] mseed;
    private static boolean mseedInitialized;
    private ECPrivateKey signKey;
    private MessageDigest sha256;
    private Signature signature;
    private KeyAgreement ecdh;
    private AESKey transportKeySecret;
    private static KeyPair transportKey;
    private Cipher aesCBCCipher;

    private byte[] main500;
    private byte[] scratch328;

    private static Display display;
    private static TX2 tx2;
    private static BIP bip;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new blackCardApplet().register();
    }

    public blackCardApplet() {

        display = new Display();
        tx2 = new TX2();
        bip = new BIP();

        pin = new OwnerPIN((byte) 3, PIN_SIZE);
        pin.update(defaultPIN, (short) 0, PIN_SIZE);
        pin.resetAndUnblock();

        puk = new OwnerPIN((byte) 15, PUK_SIZE);

        yesCode = new OwnerPIN((byte) 3, PIN_SIZE);

        label = new byte[LABEL_SIZE_MAX];
        labelLength = Util.arrayCopyNonAtomic(defaultLabel, (short) 0, label, (short) 0, (short) defaultLabel.length);

        randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

        serialNumber = new byte[SERIALNUMBER_SIZE];
        randomData.generateData(serialNumber, (short) 0, SERIALNUMBER_SIZE);

        tempSerialNumber = JCSystem.makeTransientByteArray(SERIALNUMBER_SIZE, JCSystem.CLEAR_ON_DESELECT);

        mseed = new byte[64];
        mseedInitialized = false;
        signKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
        // new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);

        transportKey = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);

        main500 = JCSystem.makeTransientByteArray((short) 500, JCSystem.CLEAR_ON_DESELECT);
        scratch328 = JCSystem.makeTransientByteArray((short) 328, JCSystem.CLEAR_ON_DESELECT);

        sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        signature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        ecdh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
        transportKeySecret = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
        aesCBCCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            display.displayWelcome(version, label, labelLength, scratch328);
            return;
        }

        byte[] buf = apdu.getBuffer();
        byte cla = buf[OFFSET_CLA];
        byte ins = buf[OFFSET_INS];
        byte p1 = buf[OFFSET_P1];
        byte p2 = buf[OFFSET_P2];

        if (cla != (byte) 0x00) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        try {
            if ((ins == (byte) 0xB1) && (p1 == (byte) 0x2F) && (p2 == (byte) 0xE2)) {
                processGetSerialNumber(apdu);
            } else if ((ins == (byte) 0xB1) && (p1 == (byte) 0xBC) && (p2 == (byte) 0x01)) {
                processGetVersion(apdu);
            } else if ((ins == (byte) 0xB1) && (p1 == (byte) 0xBC) && (p2 == (byte) 0x02)) {
                processGetLabel(apdu);
            } else if ((ins == (byte) 0xD1) && (p1 == (byte) 0xBC) && (p2 == (byte) 0x02)) {
                processSetLabel(apdu);
            } else if ((ins == (byte) 0x20) && (p1 == (byte) 0x00) && (p2 == (byte) 0x00)) {
                processVerifyPIN(apdu);
            } else if ((ins == (byte) 0x24) && (p1 == (byte) 0x01) && (p2 == (byte) 0x00)) {
                processChangePIN(apdu);
            } else if ((ins == (byte) 0x24) && (p1 == (byte) 0x31) && (p2 == (byte) 0x00)) {
                processSetPUK(apdu);
            } else if ((ins == (byte) 0x2C) && (p1 == (byte) 0x01) && (p2 == (byte) 0x00)) {
                processUnblockPIN(apdu);
            } else if ((ins == (byte) 0x46) && (p1 == (byte) 0x84) && (p2 == (byte) 0x01)) {
                processGenerateMasterSeed(apdu);
            } else if ((ins == (byte) 0xB1) && (p1 == (byte) 0xBC) && (p2 == (byte) 0x03)) {
                processGetAddress(apdu);
            } else if ((ins == (byte) 0x46) && (p1 == (byte) 0xC4) && (p2 == (byte) 0x01)) {
                processRemoveMasterSeed(apdu);
            } else if ((ins == (byte) 0x2A) && (p1 == (byte) 0x9E) && (p2 == (byte) 0x9A)) {
                processSignTransaction(apdu);
            } else if ((ins == (byte) 0x46) && (p1 == (byte) 0x80) && (p2 == (byte) 0x00)) {
                processGenerateTransportKey(apdu);
            } else if ((ins == (byte) 0xD1) && (p1 == (byte) 0xBC) && (p2 == (byte) 0x04)) {
                processImportTransportKeyPublic(apdu);
            } else if ((ins == (byte) 0x2A) && (p1 == (byte) 0x86) && (p2 == (byte) 0x80)) {
                processExportMasterSeed(apdu);
            } else if ((ins == (byte) 0x2A) && (p1 == (byte) 0x80) && (p2 == (byte) 0x86)) {
                processImportMasterSeed(apdu);
            } else if ((ins == (byte) 0xD1) && (p1 == (byte) 0xBC) && (p2 == (byte) 0x05)) {
                processImportMasterSeedPalin(apdu);
            } else if ((ins == (byte) 0xB1) && (p1 == (byte) 0xBC) && (p2 == (byte) 0x06)) {
                processGetAddressList(apdu);
            }

            else if (ins == (byte) 0xAA) {
                test(apdu);
            }

            else {
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        } catch (SystemException e) {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
    }

    private void test(APDU apdu) {
        apdu.setIncomingAndReceive();
        byte[] buf = apdu.getBuffer();
        short lc = apdu.getIncomingLength();

        byte[] path = { 0x6D, 0x2C, 0x01, 0x00, 0x00, 0x00, 0x00 };

        // byte[] hash = { (byte) 0x9f, 0x58, (byte) 0x8a, 0x33, (byte) 0xd6, 0x26,
        // (byte) 0xac, (byte) 0xe9, 0x4e, 0x3d,
        // (byte) 0xbd, 0x1e, 0x24, 0x52, 0x5d, (byte) 0xc3, (byte) 0xa6, (byte) 0xb5,
        // (byte) 0xab, (byte) 0x81,
        // (byte) 0x90, (byte) 0xb3, (byte) 0xf4, 0x43, 0x5c, 0x18, (byte) 0xf1, (byte)
        // 0xd2, 0x55, (byte) 0xe7,
        // 0x42, 0x47 };
        byte[] hash = { (byte) 0xa6, (byte) 0xbb, 0x43, 0x7f, 0x51, (byte) 0xb1, 0x50, (byte) 0xfb, 0x04, 0x35, 0x34,
                0x68, (byte) 0x83, 0x09, (byte) 0xc6, 0x60, 0x65, 0x7e, (byte) 0xe0, 0x2d, 0x3e, 0x79, (byte) 0xdf,
                0x47, 0x43, (byte) 0x8a, 0x6a, (byte) 0xcc, (byte) 0xfe, 0x4a, (byte) 0xe9, 0x78 };

        bip.bip44DerivePath(mseed, (short) 0, MSEED_SIZE, path, (short) 0, main500, (short) 0, (short) 1, main500,
                (short) 32, scratch328, (short) 0);

        short publicKeyLength = bip.ec256PrivateKeyToPublicKey(main500, (short) 0, main500, (short) 100, false);

        Secp256k1.setCommonCurveParameters(signKey);
        signKey.setS(main500, (short) 0, (short) 32);
        signature.init(signKey, Signature.MODE_SIGN);
        short signatureLen = signature.sign(hash, (short) 0, (short) 32, main500, (short) 0);

        apdu.setOutgoing();
        apdu.setOutgoingLength(signatureLen);
        apdu.sendBytesLong(main500, (short) 0, signatureLen);

        // apdu.setIncomingAndReceive();
        // byte[] buf = apdu.getBuffer();
        // short lc = apdu.getIncomingLength();

        // Util.arrayCopyNonAtomic(buf, OFFSET_CDATA, hashBuffer, (short) 0, lc);

        // bip.bip32GenerateMasterKey(mseed, (short) 0, MSEED_SIZE, BIP.BITCOIN,
        // mainBuffer, (short) 0);

        // bip.bip32DerivePrivateKey(mainBuffer, (short) 0, (short) 0, true, mainBuffer,
        // (short) 0, scratchBuffer,
        // (short) 0);

        // short pubKeyLen = bip.ec256PrivateKeyToPublicKey(mainBuffer, (short) 0,
        // mainBuffer, (short) 70, true);

        // apdu.setOutgoing();
        // apdu.setOutgoingLength(pubKeyLen);
        // apdu.sendBytesLong(mainBuffer, (short) 70, pubKeyLen);

        // short masterPrivateKeyLength = ((ECPrivateKey)
        // masterKey.getPrivate()).getS(mainBuffer, (short) 0);

        // apdu.setOutgoing();
        // apdu.setOutgoingLength(masterPrivateKeyLength);
        // apdu.sendBytesLong(mainBuffer, (short) 0, masterPrivateKeyLength);

        // rsaKey.genKeyPair();

        // crtKey.genKeyPair();

        // apdu.setIncomingAndReceive();
        // byte[] buf = apdu.getBuffer();
        // short lc = apdu.getIncomingLength();

        // Util.arrayCopyNonAtomic(buf, OFFSET_CDATA, mainBuffer, (short) 0, lc);

        // short b58Len = Base58.encode(mainBuffer, (short) 0, lc, scratchBuffer,
        // (short) 0, scratchBuffer, (short) 100);

        // apdu.setOutgoing();
        // apdu.setOutgoingLength(b58Len);
        // apdu.sendBytesLong(scratchBuffer, (short) 0, b58Len);
    }

    private void processGetSerialNumber(APDU apdu) {
        if (tempSerialNumber[0] == (byte) 0x00) {
            if (serialNumber == null) {
                ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
            }

            Util.arrayCopyNonAtomic(serialNumber, (short) 0, tempSerialNumber, (short) 0, SERIALNUMBER_SIZE);
        }

        apdu.setOutgoing();
        apdu.setOutgoingLength((short) SERIALNUMBER_SIZE);
        apdu.sendBytesLong(tempSerialNumber, (short) 0, SERIALNUMBER_SIZE);
    }

    private void processGetVersion(APDU apdu) {
        short versionLen = (short) version.length;
        apdu.setOutgoing();
        apdu.setOutgoingLength(versionLen);
        apdu.sendBytesLong(version, (short) 0, versionLen);
    }

    private void processGetLabel(APDU apdu) {
        apdu.setOutgoing();
        apdu.setOutgoingLength(labelLength);
        apdu.sendBytesLong(label, (short) 0, labelLength);
    }

    private void processSetLabel(APDU apdu) {
        if (pin.isValidated() == false) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        apdu.setIncomingAndReceive();
        byte[] buf = apdu.getBuffer();
        short lc = apdu.getIncomingLength();

        if (lc > LABEL_SIZE_MAX) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        labelLength = Util.arrayCopyNonAtomic(buf, OFFSET_CDATA, label, (short) 0, lc);
    }

    private void processVerifyPIN(APDU apdu) {
        apdu.setIncomingAndReceive();
        byte[] buf = apdu.getBuffer();
        short lc = apdu.getIncomingLength();
        if (lc != PIN_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        if (pin.check(buf, OFFSET_CDATA, PIN_SIZE) == false) {
            ISOException.throwIt((short) (SW_PIN_INCORRECT_TRIES_LEFT | pin.getTriesRemaining()));
        }
    }

    private void processChangePIN(APDU apdu) {
        if (pin.isValidated() == false) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        apdu.setIncomingAndReceive();
        byte[] buf = apdu.getBuffer();
        short lc = apdu.getIncomingLength();
        if (lc != PIN_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        pin.update(buf, OFFSET_CDATA, PIN_SIZE);
        pin.resetAndUnblock();
    }

    private void processSetPUK(APDU apdu) {
        if (isPersonalized == true) {
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }

        apdu.setIncomingAndReceive();
        byte[] buf = apdu.getBuffer();
        short lc = apdu.getIncomingLength();
        if (lc != PUK_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        puk.update(buf, OFFSET_CDATA, PUK_SIZE);
        puk.resetAndUnblock();

        isPersonalized = true;
    }

    private void processUnblockPIN(APDU apdu) {
        apdu.setIncomingAndReceive();
        byte[] buf = apdu.getBuffer();
        short lc = apdu.getIncomingLength();
        if (lc != PUK_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        if (puk.check(buf, OFFSET_CDATA, PUK_SIZE) == false) {
            ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        pin.update(defaultPIN, (short) 0, PIN_SIZE);
        pin.resetAndUnblock();

        puk.reset();
    }

    private void processGenerateMasterSeed(APDU apdu) {
        if (pin.isValidated() == false) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        if (mseedInitialized == true) {
            ISOException.throwIt(SW_COMMAND_NOT_ALLOWED);
        }

        do {
            // entropy => mseed
            randomData.generateData(mseed, (short) 0, MSEED_SIZE);

        } while (!bip.bip32GenerateMasterKey(mseed, (short) 0, MSEED_SIZE, main500, (short) 0));

        mseedInitialized = true;
    }

    private void processGetAddress(APDU apdu) {
        // if (pin.isValidated() == false) {
        // ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        // }

        // if (masterKey.getPrivate().isInitialized() == false) {
        // ISOException.throwIt(SW_COMMAND_NOT_ALLOWED);
        // }

        // short publicKeyLength = ((ECPublicKey)
        // masterKey.getPublic()).getW(mainBuffer, (short) 0);
        // short addressSize = publicKeyToAddress(mainBuffer, (short) 0,
        // publicKeyLength, mainBuffer, (short) 50);

        // display.displayAddress(BTCTestNet, mainBuffer, (short) 50, addressSize,
        // scratchBuffer);

        // apdu.setOutgoing();
        // apdu.setOutgoingLength(addressSize);
        // apdu.sendBytesLong(mainBuffer, (short) 50, addressSize);
    }

    private void processRemoveMasterSeed(APDU apdu) {
        if (pin.isValidated() == false) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        Util.arrayFillNonAtomic(mseed, (short) 0, MSEED_SIZE, (byte) 0);

        mseedInitialized = false;
    }

    private short toBigEndian(byte[] leNumber, short leNumberOffset, byte[] beNumber, short beNumberOffset,
            short length) {
        for (short i = 0; i < length; i++) {
            beNumber[beNumberOffset + length - 1 - i] = leNumber[leNumberOffset + i];
        }
        return (short) (beNumberOffset + length);
    }

    private void processSignTransaction(APDU apdu) {
        if (pin.isValidated() == false) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        apdu.setIncomingAndReceive();
        byte[] buf = apdu.getBuffer();
        short lc = apdu.getIncomingLength();

        short fundIndex = OFFSET_CDATA; // 8B
        short spendIndex = OFFSET_CDATA + 8; // 8B
        short feeIndex = OFFSET_CDATA + 16; // 8B
        short destAddressIndex = OFFSET_CDATA + 24; // 25B
        short changeKeyPathIndex = OFFSET_CDATA + 49; // 7B
        short inputSectionIndex = OFFSET_CDATA + 56; // 1B + n*66B
        short inputCount = buf[inputSectionIndex];
        short signerKeyPathsIndex = (short) (inputSectionIndex + 1 + (short) (inputCount * 66)); // n*7B

        short moffset = 0;
        // version 01000000
        main500[moffset++] = 0x01;
        main500[moffset++] = 0x00;
        main500[moffset++] = 0x00;
        main500[moffset++] = 0x00;
        // inputs
        main500[moffset++] = buf[inputSectionIndex]; // input count
        // fill after sign
        // output count
        short outputIndex = (short) ((short) main500.length - 77);// Output length
        moffset = outputIndex;
        main500[moffset++] = 0x02;
        // spend value (big endian)
        moffset = toBigEndian(buf, spendIndex, main500, moffset, (short) 8);
        // P2SH dest pub key hash
        Util.arrayCopyNonAtomic(buf, (short) (destAddressIndex + 1), P2PKH, (short) 4, (short) 20);
        moffset = Util.arrayCopyNonAtomic(P2PKH, (short) 0, main500, moffset, (short) (P2PKH.length));
        // change value (big endian) : change = fund - spend - fee;
        MathMod256.sub(scratch328, (short) 0, buf, fundIndex, buf, spendIndex, (short) 8);
        MathMod256.sub(scratch328, (short) 0, scratch328, (short) 0, buf, feeIndex, (short) 8);
        moffset = toBigEndian(scratch328, (short) 0, main500, moffset, (short) 8);
        // P2SH change pub key hash
        bip.bip44DerivePath(mseed, (short) 0, MSEED_SIZE, buf, changeKeyPathIndex, scratch328, (short) 0, (short) 1,
                scratch328, (short) 32, scratch328, (short) 60);
        // addressList: 1B len + 25B address
        Util.arrayCopyNonAtomic(scratch328, (short) (32 + 1 + 1), P2PKH, (short) 4, (short) 20);
        moffset = Util.arrayCopyNonAtomic(P2PKH, (short) 0, main500, moffset, (short) (P2PKH.length));
        // locktime 00000000
        main500[moffset++] = 0x00;
        main500[moffset++] = 0x00;
        main500[moffset++] = 0x00;
        main500[moffset++] = 0x00;
        // hashtype 01000000
        main500[moffset++] = 0x01;
        main500[moffset++] = 0x00;
        main500[moffset++] = 0x00;
        main500[moffset++] = 0x00;

        moffset = 5;// begin of outputs
        // for (...)
        // 32B hash + 4B UTXO
        moffset = Util.arrayCopyNonAtomic(buf, (short) (inputSectionIndex + 1), main500, moffset, (short) 36);

        sha256.reset();
        sha256.update(main500, (short) 0, (short) 4);
        sha256.update(buf, inputSectionIndex, (short) (1 + 66));
        sha256.doFinal(main500, outputIndex, (short) (77), scratch328, (short) 0);
        // hold tx hash in scratch 0..31

        bip.bip44DerivePath(mseed, (short) 0, MSEED_SIZE, buf, signerKeyPathsIndex, scratch328, (short) 32, (short) 1,
                scratch328, (short) 64, scratch328, (short) 90);// hold prikey in scratch 32..63 [32]

        Secp256k1.setCommonCurveParameters(signKey);
        signKey.setS(scratch328, (short) 32, (short) 32);
        signature.init(signKey, Signature.MODE_SIGN);
        short scriptLenIndex = moffset;
        moffset++;// 1B script Len
        short signatureLen = signature.sign(scratch328, (short) 0, (short) 32, main500, (short) (moffset + 1));
        main500[moffset] = (byte) (signatureLen + 1);// sig len + 1
        moffset += signatureLen + 1;
        main500[moffset++] = 0x01;// hash type
        short pubKeyLen = bip.ec256PrivateKeyToPublicKey(scratch328, (short) 32, main500, (short) (moffset + 1), true);
        main500[moffset++] = (byte) pubKeyLen;
        moffset += pubKeyLen;
        // x = 1B [sig len byte] + sigLen + 1B [hash type] + 1B [pubkey Len] + pubKeyLen
        main500[scriptLenIndex] = (byte) (3 + signatureLen + pubKeyLen);
        // 63 = 1B len + 32B hash + 4B UTXO + 26B script
        moffset = Util.arrayCopyNonAtomic(buf, (short) (inputSectionIndex + 63), main500, moffset, (short) 4);// sequence
        // end for

        moffset = Util.arrayCopyNonAtomic(main500, outputIndex, main500, moffset, (short) 73);

        apdu.setOutgoing();
        apdu.setOutgoingLength(moffset);
        apdu.sendBytesLong(main500, (short) 0, moffset);
    }

    private short generateKCV(byte[] inBubber, short inOffset, short inLength, byte[] outBuffer, short outOffset) {
        sha256.reset();
        short sha256Len = sha256.doFinal(inBubber, inOffset, inLength, scratch328, (short) 0);

        Ripemd160.hash32(scratch328, (short) 0, scratch328, sha256Len, scratch328, (short) 60);
        short ripemd160Len = (short) 20;

        short b58Len = Base58.encode(scratch328, sha256Len, ripemd160Len, outBuffer, outOffset, scratch328, (short) 60);

        return b58Len;
    }

    private void processGenerateTransportKey(APDU apdu) {
        if (pin.isValidated() == false) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        Secp256k1.setCommonCurveParameters(((ECPrivateKey) transportKey.getPrivate()));
        Secp256k1.setCommonCurveParameters(((ECPublicKey) transportKey.getPublic()));
        transportKey.genKeyPair();

        short publicKeyLength = ((ECPublicKey) transportKey.getPublic()).getW(main500, (short) 0);

        short kcvLen = generateKCV(main500, (short) 0, publicKeyLength, main500, publicKeyLength);

        display.displayText(main500, publicKeyLength, kcvLen, scratch328, (short) 0);

        apdu.setOutgoing();
        apdu.setOutgoingLength(publicKeyLength);
        apdu.sendBytesLong(main500, (short) 0, publicKeyLength);
    }

    private void processImportTransportKeyPublic(APDU apdu) {
        if (pin.isValidated() == false) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        if (mseedInitialized == false) {
            ISOException.throwIt(SW_COMMAND_NOT_ALLOWED);
        }

        apdu.setIncomingAndReceive();
        byte[] buf = apdu.getBuffer();
        short lc = apdu.getIncomingLength();
        if (lc != (short) 65) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        short publicKeyLength = lc;

        // Get backup trnsport key public : publicKeyLength = lc = 65
        Util.arrayCopyNonAtomic(buf, OFFSET_CDATA, main500, (short) 0, publicKeyLength);

        // Generate main wallet transport key
        Secp256k1.setCommonCurveParameters(((ECPrivateKey) transportKey.getPrivate()));
        Secp256k1.setCommonCurveParameters(((ECPublicKey) transportKey.getPublic()));
        transportKey.genKeyPair();

        ecdh.init(transportKey.getPrivate());
        short resultLen = ecdh.generateSecret(main500, (short) 0, publicKeyLength, main500, publicKeyLength);
        sha256.reset();
        sha256.doFinal(main500, publicKeyLength, resultLen, scratch328, (short) 0);
        transportKeySecret.setKey(scratch328, (short) 0);

        short kcvLen = generateKCV(main500, (short) 0, publicKeyLength, main500, publicKeyLength);

        // Generate yesCode
        // for (short i = 0; i < PIN_SIZE; i++) {
        // do {
        // randomData.generateData(scratchBuffer, i, (short) 1);
        // } while (scratchBuffer[i] < 0);
        // byte b = (byte) (scratchBuffer[i] % 10);
        // scratchBuffer[i] = (byte) (b + 0x30);
        // }
        // yesCode.update(scratchBuffer, (short) 0, PIN_SIZE);

        // yesCode.update(defaultPIN, (short) 0, PIN_SIZE);
        // yesCode.resetAndUnblock();

        // replace b58Len by (publicKeyLength + kcvLen)
        // mainBuffer[b58Len] = Display.NEWLINE;
        // Util.arrayCopyNonAtomic(scratchBuffer, (short) 0, mainBuffer, (short) (b58Len
        // + 1), PIN_SIZE);
        // display.displayText(mainBuffer, (short) 0, (short) (b58Len + 1 + PIN_SIZE),
        // scratchBuffer, (short) 0);

        display.displayText(main500, publicKeyLength, kcvLen, scratch328, (short) 0);
    }

    private void processExportMasterSeed(APDU apdu) {
        if (pin.isValidated() == false) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        if (mseedInitialized == false) {
            ISOException.throwIt(SW_COMMAND_NOT_ALLOWED);
        }

        apdu.setIncomingAndReceive();
        byte[] buf = apdu.getBuffer();
        short lc = apdu.getIncomingLength();
        // if (lc != PIN_SIZE) {
        // ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        // }
        // if (yesCode.check(buf, OFFSET_CDATA, PIN_SIZE) == false) {
        // ISOException.throwIt((short) (SW_PIN_INCORRECT_TRIES_LEFT |
        // yesCode.getTriesRemaining()));
        // }

        aesCBCCipher.init(transportKeySecret, Cipher.MODE_ENCRYPT);

        // BackupPackagae ::= SEQUENCE {
        // ECC256PublicKey INTEGER,
        // AES256Cipher INTEGER
        // }
        main500[0] = (byte) 0x30;// SEQUENCE
        main500[1] = (byte) 0x85;// length:133
        main500[2] = (byte) 0x02;// INTEGER
        main500[3] = (byte) 0x41;// length : 65
        // mainBuffer[4..68]//ECC256PublicKey: 65 bytes
        ((ECPublicKey) transportKey.getPublic()).getW(main500, (short) 4);
        main500[69] = (byte) 0x02;// INTEGER
        main500[70] = (byte) 0x40;// length: 64
        // mainBuffer[71..134]//AES256Cipher: 64 bytes
        aesCBCCipher.doFinal(mseed, (short) 0, MSEED_SIZE, main500, (short) 71);

        yesCode.reset();
        transportKey.getPrivate().clearKey();
        transportKeySecret.clearKey();

        apdu.setOutgoing();
        apdu.setOutgoingLength((short) 135);
        apdu.sendBytesLong(main500, (short) 0, (short) 135);
    }

    private void processImportMasterSeed(APDU apdu) {
        if (pin.isValidated() == false) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        if (mseedInitialized == true) {
            ISOException.throwIt(SW_COMMAND_NOT_ALLOWED);
        }

        if (transportKey.getPrivate().isInitialized() == false) {
            ISOException.throwIt(SW_COMMAND_NOT_ALLOWED);
        }

        apdu.setIncomingAndReceive();
        byte[] buf = apdu.getBuffer();
        short lc = apdu.getIncomingLength();
        if (lc != (short) 135) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Get main wallet trnsport key public : 65
        Util.arrayCopyNonAtomic(buf, (short) (OFFSET_CDATA + 4), scratch328, (short) 0, (short) 65);

        ecdh.init(transportKey.getPrivate());
        short resultLen = ecdh.generateSecret(scratch328, (short) 0, (short) 65, scratch328, (short) 65);
        sha256.reset();
        sha256.doFinal(scratch328, (short) 65, resultLen, scratch328, (short) (65 + resultLen));
        transportKeySecret.setKey(scratch328, (short) (65 + resultLen));

        aesCBCCipher.init(transportKeySecret, Cipher.MODE_DECRYPT);
        aesCBCCipher.doFinal(buf, (short) (OFFSET_CDATA + 71), MSEED_SIZE, mseed, (short) 0);
        mseedInitialized = true;

        transportKey.getPrivate().clearKey();
        transportKeySecret.clearKey();
    }

    // Secp256k1.setCommonCurveParameters(((ECPrivateKey) masterKey.getPrivate()));
    // Secp256k1.setCommonCurveParameters(((ECPublicKey) masterKey.getPublic()));
    // ((ECPrivateKey) masterKey.getPrivate()).setS(mainBuffer, (short) 0,
    // cipherLength);

    private void processImportMasterSeedPalin(APDU apdu) {
        if (pin.isValidated() == false) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        if (mseedInitialized == true) {
            ISOException.throwIt(SW_COMMAND_NOT_ALLOWED);
        }

        apdu.setIncomingAndReceive();
        byte[] buf = apdu.getBuffer();
        short lc = apdu.getIncomingLength();

        if (lc != MSEED_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        Util.arrayCopyNonAtomic(buf, OFFSET_CDATA, main500, (short) 0, MSEED_SIZE);

        if (!bip.bip32GenerateMasterKey(main500, (short) 0, MSEED_SIZE, main500, MSEED_SIZE)) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        Util.arrayCopyNonAtomic(buf, OFFSET_CDATA, mseed, (short) 0, MSEED_SIZE);

        mseedInitialized = true;
    }

    private void processGetAddressList(APDU apdu) {
        if (pin.isValidated() == false) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        if (mseedInitialized == false) {
            ISOException.throwIt(SW_COMMAND_NOT_ALLOWED);
        }

        apdu.setIncomingAndReceive();
        byte[] buf = apdu.getBuffer();
        short lc = apdu.getIncomingLength();

        if (lc != (byte) 0x08) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        short reslutLen = bip.bip44DerivePath(mseed, (short) 0, MSEED_SIZE, buf, OFFSET_CDATA, main500, (short) 0,
                buf[OFFSET_CDATA + 7], main500, (short) 32, scratch328, (short) 0);

        // short reslutLen = bip.bip44DerivePath(mseed, (short) 0, MSEED_SIZE, buf,
        // OFFSET_CDATA, scratch328, (short) 0,
        // (short) 1, main500, (short) 32, scratch328, (short) 60);

        apdu.setOutgoing();
        apdu.setOutgoingLength(reslutLen);
        apdu.sendBytesLong(main500, (short) 32, reslutLen);
    }

    private void processECCSign(APDU apdu) {
        /*
         * apdu.setIncomingAndReceive(); byte[] buf = apdu.getBuffer(); //short lc =
         * (short)(buf[OFFSET_LC]); short lc = apdu.getIncomingLength();
         * 
         * Util.arrayCopyNonAtomic(buf, OFFSET_CDATA, inputBuffer, (short) 0, lc);
         * 
         * sha256.reset(); sha256.doFinal(inputBuffer, (short)0, lc, hashBuffer,
         * (short)0);
         * 
         * /*KeyPair masterKey=null; masterKey= new KeyPair(KeyPair.ALG_EC_FP,
         * KeyBuilder.LENGTH_EC_FP_256); masterKey.genKeyPair(); privateKey =
         * (ECPrivateKey)masterKey.getPrivate();
         */

        /*
         * signature.init(privateKey, Signature.MODE_SIGN); short sigLen =
         * signature.sign(hashBuffer, (short)0, (short)32, outputBuffer, (short)0);
         * 
         * apdu.setOutgoing(); apdu.setOutgoingLength((short) sigLen);
         * apdu.sendBytesLong(outputBuffer, (short) 0, sigLen);
         */
    }

}
