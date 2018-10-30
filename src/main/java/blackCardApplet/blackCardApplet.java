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
    private static final short BUFFER_SIZE_MAX = 200;// 500;// 1000;
    private static final short HASH_SIZE = 32;
    private static final short SCRATCH_SIZE = 300;
    private static final short MSEED_SIZE = 64;

    public static final short BTCTestNet = 1;
    public static final short BTCMainNet = 2;

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

    private static byte[] mseed;
    private static boolean mseedInitialized;
    private KeyPair signKey;
    private MessageDigest sha256;
    private Signature eccSignature;
    private KeyAgreement ecdh;
    private AESKey transportKeySecret;
    private static KeyPair transportKey;
    private Cipher aesCBCCipher;

    private byte[] mainBuffer;
    private byte[] hashBuffer;
    private byte[] scratchBuffer;// Should not be used as input to a function

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
        signKey = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);

        transportKey = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);

        mainBuffer = JCSystem.makeTransientByteArray(BUFFER_SIZE_MAX, JCSystem.CLEAR_ON_DESELECT);
        hashBuffer = JCSystem.makeTransientByteArray(HASH_SIZE, JCSystem.CLEAR_ON_DESELECT);
        scratchBuffer = JCSystem.makeTransientByteArray(SCRATCH_SIZE, JCSystem.CLEAR_ON_DESELECT);

        sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        eccSignature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        ecdh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
        transportKeySecret = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
        aesCBCCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            display.displayWelcome(version, label, labelLength, scratchBuffer);
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

        if (lc != 7) {
            return;
        }

        bip.bip44DerivePath(mseed, (short) 0, MSEED_SIZE, buf, OFFSET_CDATA, mainBuffer, (short) 0, (short) 1,
                mainBuffer, (short) 32, scratchBuffer, (short) 0);

        short pubKeyLen = bip.ec256PrivateKeyToPublicKey(mainBuffer, (short) 0, mainBuffer, (short) 70, true);

        apdu.setOutgoing();
        apdu.setOutgoingLength(pubKeyLen);
        apdu.sendBytesLong(mainBuffer, (short) 70, pubKeyLen);

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

        } while (!bip.bip32GenerateMasterKey(mseed, (short) 0, MSEED_SIZE, mainBuffer, (short) 0));

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

    private void processSignTransaction(APDU apdu) {
        if (pin.isValidated() == false) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        /*
         * apdu.setIncomingAndReceive(); byte[] buf = apdu.getBuffer(); short lc =
         * apdu.getIncomingLength();
         * 
         * if(lc > BUFFER_SIZE_MAX){ ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);}
         * 
         * //Util.arrayCopyNonAtomic(buf, OFFSET_CDATA, mainBuffer, (short) 0, lc);
         * 
         * tx2.decode(buf, OFFSET_CDATA);
         * 
         * sha256.reset(); sha256.doFinal(buf, OFFSET_CDATA, lc, hashBuffer, (short)0);
         * 
         * signature.init(masterPrivateKey, Signature.MODE_SIGN); short sigLen =
         * signature.sign(hashBuffer, (short)0, (short)32, scratchBuffer, (short)0);
         * 
         * 
         * 
         * //Util.arrayCopyNonAtomic(buf, OFFSET_CDATA, mainBuffer, (short) 0,
         * (short)(tx2.inputScript[0] - OFFSET_CDATA); short offset = (short)0;
         * Util.arrayCopyNonAtomic(buf, tx2.version, mainBuffer, offset,
         * tx2.INT32_SIZE); offset += tx2.INT32_SIZE; mainBuffer[offset] =
         * tx2.inputCount; offset += tx2.BYTE_SIZE;
         * 
         * short SIGNED_INPUT_SCRIPT_SIZE = (short)139; for(short i=0 ; i<tx2.inputCount
         * ; i++) { Util.arrayCopyNonAtomic(buf, tx2.inputPreTxHash[0], mainBuffer,
         * offset, tx2.HASH_SIZE); offset += tx2.HASH_SIZE; Util.arrayCopyNonAtomic(buf,
         * tx2.inputUTXOindex[0], mainBuffer, offset, tx2.INT32_SIZE); offset +=
         * tx2.INT32_SIZE; offset += SIGNED_INPUT_SCRIPT_SIZE;
         * Util.arrayCopyNonAtomic(buf, tx2.inputSequence[0], mainBuffer, offset,
         * tx2.INT32_SIZE); offset += tx2.INT32_SIZE; }
         * 
         * Util.arrayCopyNonAtomic(buf, tx2.outputCount, mainBuffer, offset,
         * tx2.BYTE_SIZE); offset += tx2.BYTE_SIZE; Util.arrayCopyNonAtomic(buf,
         * tx2.spendValue, mainBuffer, offset, tx2.INT64_SIZE); offset +=
         * tx2.INT64_SIZE; Util.arrayCopyNonAtomic(buf, tx2.spendScript, mainBuffer,
         * offset, tx2.SCRIPT_SIZE); offset += tx2.SCRIPT_SIZE;
         * Util.arrayCopyNonAtomic(buf, tx2.changeValue, mainBuffer, offset,
         * tx2.INT64_SIZE); offset += tx2.INT64_SIZE; Util.arrayCopyNonAtomic(buf,
         * tx2.changeScript, mainBuffer, offset, tx2.SCRIPT_SIZE); offset +=
         * tx2.SCRIPT_SIZE; Util.arrayCopyNonAtomic(buf, tx2.lockTime, mainBuffer,
         * offset, tx2.INT32_SIZE); offset += tx2.INT32_SIZE;
         * 
         * 
         * apdu.setOutgoing(); apdu.setOutgoingLength((short) sigLen);
         * apdu.sendBytesLong(scratchBuffer, (short) 0, sigLen);
         */
    }

    private short generateKCV(byte[] inBubber, short inOffset, short inLength, byte[] outBuffer, short outOffset) {
        sha256.reset();
        short sha256Len = sha256.doFinal(inBubber, inOffset, inLength, scratchBuffer, (short) 0);

        Ripemd160.hash32(scratchBuffer, (short) 0, scratchBuffer, sha256Len, scratchBuffer, (short) 60);
        short ripemd160Len = (short) 20;

        short b58Len = Base58.encode(scratchBuffer, sha256Len, ripemd160Len, outBuffer, outOffset, scratchBuffer,
                (short) 60);

        return b58Len;
    }

    private void processGenerateTransportKey(APDU apdu) {
        if (pin.isValidated() == false) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        Secp256k1.setCommonCurveParameters(((ECPrivateKey) transportKey.getPrivate()));
        Secp256k1.setCommonCurveParameters(((ECPublicKey) transportKey.getPublic()));
        transportKey.genKeyPair();

        short publicKeyLength = ((ECPublicKey) transportKey.getPublic()).getW(mainBuffer, (short) 0);

        short kcvLen = generateKCV(mainBuffer, (short) 0, publicKeyLength, mainBuffer, publicKeyLength);

        display.displayText(mainBuffer, publicKeyLength, kcvLen, scratchBuffer, (short) 0);

        apdu.setOutgoing();
        apdu.setOutgoingLength(publicKeyLength);
        apdu.sendBytesLong(mainBuffer, (short) 0, publicKeyLength);
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
        Util.arrayCopyNonAtomic(buf, OFFSET_CDATA, mainBuffer, (short) 0, publicKeyLength);

        // Generate main wallet transport key
        Secp256k1.setCommonCurveParameters(((ECPrivateKey) transportKey.getPrivate()));
        Secp256k1.setCommonCurveParameters(((ECPublicKey) transportKey.getPublic()));
        transportKey.genKeyPair();

        ecdh.init(transportKey.getPrivate());
        short resultLen = ecdh.generateSecret(mainBuffer, (short) 0, publicKeyLength, mainBuffer, publicKeyLength);
        sha256.reset();
        sha256.doFinal(mainBuffer, publicKeyLength, resultLen, hashBuffer, (short) 0);
        transportKeySecret.setKey(hashBuffer, (short) 0);

        short kcvLen = generateKCV(mainBuffer, (short) 0, publicKeyLength, mainBuffer, publicKeyLength);

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

        display.displayText(mainBuffer, publicKeyLength, kcvLen, scratchBuffer, (short) 0);
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
        mainBuffer[0] = (byte) 0x30;// SEQUENCE
        mainBuffer[1] = (byte) 0x85;// length:133
        mainBuffer[2] = (byte) 0x02;// INTEGER
        mainBuffer[3] = (byte) 0x41;// length : 65
        // mainBuffer[4..68]//ECC256PublicKey: 65 bytes
        ((ECPublicKey) transportKey.getPublic()).getW(mainBuffer, (short) 4);
        mainBuffer[69] = (byte) 0x02;// INTEGER
        mainBuffer[70] = (byte) 0x40;// length: 64
        // mainBuffer[71..134]//AES256Cipher: 64 bytes
        aesCBCCipher.doFinal(mseed, (short) 0, MSEED_SIZE, mainBuffer, (short) 71);

        yesCode.reset();
        transportKey.getPrivate().clearKey();
        transportKeySecret.clearKey();

        apdu.setOutgoing();
        apdu.setOutgoingLength((short) 135);
        apdu.sendBytesLong(mainBuffer, (short) 0, (short) 135);
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
        Util.arrayCopyNonAtomic(buf, (short) (OFFSET_CDATA + 4), scratchBuffer, (short) 0, (short) 65);

        ecdh.init(transportKey.getPrivate());
        short resultLen = ecdh.generateSecret(scratchBuffer, (short) 0, (short) 65, scratchBuffer, (short) 65);
        sha256.reset();
        sha256.doFinal(scratchBuffer, (short) 65, resultLen, hashBuffer, (short) 0);
        transportKeySecret.setKey(hashBuffer, (short) 0);

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

        Util.arrayCopyNonAtomic(buf, OFFSET_CDATA, mainBuffer, (short) 0, MSEED_SIZE);

        if (!bip.bip32GenerateMasterKey(mainBuffer, (short) 0, MSEED_SIZE, mainBuffer, MSEED_SIZE)) {
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

        short reslutLen = bip.bip44DerivePath(mseed, (short) 0, MSEED_SIZE, buf, OFFSET_CDATA, mainBuffer, (short) 0,
                buf[OFFSET_CDATA + 7], mainBuffer, (short) 32, scratchBuffer, (short) 0);

        apdu.setOutgoing();
        apdu.setOutgoingLength(reslutLen);
        apdu.sendBytesLong(mainBuffer, (short) 32, reslutLen);
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
