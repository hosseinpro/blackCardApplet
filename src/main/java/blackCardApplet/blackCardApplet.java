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
    private static final short SCRATCH_SIZE = 200;

    public static final short BTCTestNet = 1;
    public static final short BTCMainNet = 2;

    private static OwnerPIN pin;
    private static OwnerPIN puk;
    private static OwnerPIN yesCode;
    private static RandomData randomData;
    private static boolean isPersonalized;

    private static byte[] serialNumber;
    private byte[] tempSerialNumber;
    private static final byte[] version = new byte[] { (byte) 'B', (byte) ' ', (byte) '1', (byte) '.', (byte) '0' };
    private static final byte[] defaultLabel = new byte[] { (byte) 'B', (byte) 'l', (byte) 'u', (byte) 'e', (byte) 'c',
            (byte) 'a', (byte) 'r', (byte) 'd' };
    private static byte[] label;
    private static short labelLength;
    private static final byte[] defaultPIN = new byte[] { (byte) '1', (byte) '2', (byte) '3', (byte) '4' };

    private KeyPair masterKey;

    private MessageDigest sha256;
    private Signature signature;
    private KeyAgreement ecdh;
    private AESKey transportKeySecret;
    private Cipher aesCBCCipher;
    private KeyAgreement ecMultiplyHelper;

    private KeyPair transportKey;

    private byte[] mainBuffer;
    private byte[] hashBuffer;
    private byte[] scratchBuffer;

    private static Display display = null;
    private static TX2 tx2 = null;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new blackCardApplet().register();
    }

    public blackCardApplet() {

        display = new Display();
        tx2 = new TX2();

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

        masterKey = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
        Secp256k1.setCommonCurveParameters(((ECPrivateKey) masterKey.getPrivate()));
        Secp256k1.setCommonCurveParameters(((ECPublicKey) masterKey.getPublic()));

        transportKey = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);

        mainBuffer = JCSystem.makeTransientByteArray(BUFFER_SIZE_MAX, JCSystem.CLEAR_ON_DESELECT);
        hashBuffer = JCSystem.makeTransientByteArray(HASH_SIZE, JCSystem.CLEAR_ON_DESELECT);
        scratchBuffer = JCSystem.makeTransientByteArray(SCRATCH_SIZE, JCSystem.CLEAR_ON_DESELECT);

        sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        signature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        // NoXY
        // ecdh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
        ecdh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
        transportKeySecret = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
        aesCBCCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        // NoXY
        // ecMultiplyHelper =
        // KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY, false);
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
                processGenerateMasterKey(apdu);
            } else if ((ins == (byte) 0xB1) && (p1 == (byte) 0xBC) && (p2 == (byte) 0x03)) {
                processGetAddress(apdu);
            } else if ((ins == (byte) 0x46) && (p1 == (byte) 0xC4) && (p2 == (byte) 0x01)) {
                processRemoveMasterKey(apdu);
            } else if ((ins == (byte) 0x2A) && (p1 == (byte) 0x9E) && (p2 == (byte) 0x9A)) {
                processSignTransaction(apdu);
            } else if ((ins == (byte) 0x46) && (p1 == (byte) 0x80) && (p2 == (byte) 0x00)) {
                processGenerateTransportKey(apdu);
            } else if ((ins == (byte) 0xD1) && (p1 == (byte) 0xBC) && (p2 == (byte) 0x04)) {
                processImportTransportKeyPublic(apdu);
            } else if ((ins == (byte) 0x2A) && (p1 == (byte) 0x86) && (p2 == (byte) 0x80)) {
                processExportMasterKey(apdu);
            } else if ((ins == (byte) 0x2A) && (p1 == (byte) 0x80) && (p2 == (byte) 0x86)) {
                processImportMasterKey(apdu);
            } else if ((ins == (byte) 0xB1) && (p1 == (byte) 0xBC) && (p2 == (byte) 0x05)) {
                processExportWords(apdu);
            } else if ((ins == (byte) 0xD1) && (p1 == (byte) 0xBC) && (p2 == (byte) 0x05)) {
                processImportWords(apdu);
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
        short masterPrivateKeyLength = ((ECPrivateKey) masterKey.getPrivate()).getS(mainBuffer, (short) 0);

        apdu.setOutgoing();
        apdu.setOutgoingLength(masterPrivateKeyLength);
        apdu.sendBytesLong(mainBuffer, (short) 0, masterPrivateKeyLength);

        // apdu.setIncomingAndReceive();
        // byte[] buf = apdu.getBuffer();
        // short lc = apdu.getIncomingLength();

        // tx2.decode(buf, OFFSET_CDATA);

        // apdu.setOutgoing();
        // apdu.setOutgoingLength(outLen);
        // apdu.sendBytesLong(temp, (short) 0, outLen);
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

    private void processGenerateMasterKey(APDU apdu) {
        if (pin.isValidated() == false) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        if (masterKey.getPrivate().isInitialized() == true) {
            ISOException.throwIt(SW_COMMAND_NOT_ALLOWED);
        }

        masterKey.genKeyPair();
    }

    private short publicKeyToAddress(byte[] inBuf, short inOffset, short inLength, byte[] outBuf, short outOffset) {
        // https://en.bitcoin.it/w/images/en/9/9b/PubKeyToAddr.png
        sha256.reset();
        sha256.doFinal(inBuf, inOffset, inLength, hashBuffer, (short) 0);
        Ripemd160.hash32(hashBuffer, (short) 0, mainBuffer, (short) 1, scratchBuffer, (short) 0);

        // mainBuffer[0] = (byte) 0x6f;//TestNet
        mainBuffer[0] = (byte) 0x00;// MainNet

        sha256.reset();
        sha256.doFinal(mainBuffer, (short) 0, (short) 21, hashBuffer, (short) 0);
        sha256.reset();
        sha256.doFinal(hashBuffer, (short) 0, (short) 32, scratchBuffer, (short) 0);

        Util.arrayCopyNonAtomic(scratchBuffer, (short) 0, mainBuffer, (short) 21, (short) 4);

        return Base58.encode(mainBuffer, (short) 0, (short) 25, outBuf, outOffset, scratchBuffer, (short) 0);
    }

    private void processGetAddress(APDU apdu) {
        if (pin.isValidated() == false) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        if (masterKey.getPrivate().isInitialized() == false) {
            ISOException.throwIt(SW_COMMAND_NOT_ALLOWED);
        }

        short publicKeyLength = ((ECPublicKey) masterKey.getPublic()).getW(mainBuffer, (short) 0);
        short addressSize = publicKeyToAddress(mainBuffer, (short) 0, publicKeyLength, mainBuffer, (short) 50);

        display.displayAddress(BTCTestNet, mainBuffer, (short) 50, addressSize, scratchBuffer);

        apdu.setOutgoing();
        apdu.setOutgoingLength(addressSize);
        apdu.sendBytesLong(mainBuffer, (short) 50, addressSize);
    }

    private void processRemoveMasterKey(APDU apdu) {
        if (pin.isValidated() == false) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        masterKey.getPrivate().clearKey();
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

    private void processGenerateTransportKey(APDU apdu) {
        if (pin.isValidated() == false) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        transportKey.genKeyPair();

        short publicKeyLength = ((ECPublicKey) transportKey.getPublic()).getW(mainBuffer, (short) 0);

        sha256.reset();
        sha256.doFinal(mainBuffer, (short) 0, publicKeyLength, hashBuffer, (short) 0);
        short b58Len = Base58.encode(hashBuffer, (short) 0, (short) 32, scratchBuffer, (short) 0, scratchBuffer,
                (short) 50);
        display.displayText(scratchBuffer, (short) 0, b58Len, scratchBuffer, (short) 50);

        apdu.setOutgoing();
        apdu.setOutgoingLength(publicKeyLength);
        apdu.sendBytesLong(mainBuffer, (short) 0, publicKeyLength);
    }

    private void processImportTransportKeyPublic(APDU apdu) {
        if (pin.isValidated() == false) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        if (masterKey.getPrivate().isInitialized() == false) {
            ISOException.throwIt(SW_COMMAND_NOT_ALLOWED);
        }

        apdu.setIncomingAndReceive();
        byte[] buf = apdu.getBuffer();
        short lc = apdu.getIncomingLength();
        if (lc != (short) 65) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Get backup trnsport key public : 65
        Util.arrayCopyNonAtomic(buf, OFFSET_CDATA, mainBuffer, (short) 0, lc);

        // Generate origin transport key
        transportKey.genKeyPair();

        ecdh.init(transportKey.getPrivate());
        short resultLen = ecdh.generateSecret(mainBuffer, (short) 0, lc, mainBuffer, lc);
        sha256.reset();
        sha256.doFinal(mainBuffer, lc, resultLen, hashBuffer, (short) 0);
        transportKeySecret.setKey(hashBuffer, (short) 0);

        // Compute pub key hash
        sha256.reset();
        short hashLen = sha256.doFinal(mainBuffer, (short) 0, lc, hashBuffer, (short) 0);
        short b58Len = Base58.encode(hashBuffer, (short) 0, hashLen, mainBuffer, (short) 0, scratchBuffer, (short) 0);

        // Generate yesCode
        for (short i = 0; i < PIN_SIZE; i++) {
            do {
                randomData.generateData(scratchBuffer, i, (short) 1);
            } while (scratchBuffer[i] < 0);
            byte b = (byte) (scratchBuffer[i] % 10);
            scratchBuffer[i] = (byte) (b + 0x30);
        }
        yesCode.update(scratchBuffer, (short) 0, PIN_SIZE);
        yesCode.resetAndUnblock();

        mainBuffer[b58Len] = Display.NEWLINE;
        Util.arrayCopyNonAtomic(scratchBuffer, (short) 0, mainBuffer, (short) (b58Len + 1), PIN_SIZE);
        display.displayText(mainBuffer, (short) 0, (short) (b58Len + 1 + PIN_SIZE), scratchBuffer, (short) 0);
    }

    private void processExportMasterKey(APDU apdu) {
        if (pin.isValidated() == false) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        if (masterKey.getPrivate().isInitialized() == false) {
            ISOException.throwIt(SW_COMMAND_NOT_ALLOWED);
        }

        apdu.setIncomingAndReceive();
        byte[] buf = apdu.getBuffer();
        short lc = apdu.getIncomingLength();
        if (lc != PIN_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        // if (yesCode.check(buf, OFFSET_CDATA, PIN_SIZE) == false) {
        // ISOException.throwIt((short) (SW_PIN_INCORRECT_TRIES_LEFT |
        // yesCode.getTriesRemaining()));
        // }

        short masterPrivateKeyLength = ((ECPrivateKey) masterKey.getPrivate()).getS(scratchBuffer, (short) 0);

        aesCBCCipher.init(transportKeySecret, Cipher.MODE_ENCRYPT);

        // BackupPackagae ::= SEQUENCE {
        // ECC256PublicKey INTEGER,
        // AES256Cipher INTEGER
        // }
        mainBuffer[0] = (byte) 0x30;// SEQUENCE
        mainBuffer[1] = (byte) 0x65;// length:101
        mainBuffer[2] = (byte) 0x02;// INTEGER
        mainBuffer[3] = (byte) 0x41;// length : 65
        // mainBuffer[4..68]//ECC256PublicKey: 65 bytes
        ((ECPublicKey) transportKey.getPublic()).getW(mainBuffer, (short) 4);
        mainBuffer[69] = (byte) 0x02;// INTEGER
        mainBuffer[70] = (byte) 0x20;// length: 32
        // mainBuffer[71..102]//AES256Cipher: 32 bytes
        aesCBCCipher.doFinal(scratchBuffer, (short) 0, masterPrivateKeyLength, mainBuffer, (short) 71);

        yesCode.reset();
        transportKey.getPrivate().clearKey();
        transportKeySecret.clearKey();

        apdu.setOutgoing();
        apdu.setOutgoingLength((short) 103);
        apdu.sendBytesLong(mainBuffer, (short) 0, (short) 103);
    }

    private void processImportMasterKey(APDU apdu) {
        if (pin.isValidated() == false) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        if (masterKey.getPrivate().isInitialized() == true) {
            ISOException.throwIt(SW_COMMAND_NOT_ALLOWED);
        }

        if (transportKey.getPrivate().isInitialized() == false) {
            ISOException.throwIt(SW_COMMAND_NOT_ALLOWED);
        }

        apdu.setIncomingAndReceive();
        byte[] buf = apdu.getBuffer();
        short lc = apdu.getIncomingLength();
        if (lc != (short) 103) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Get origin trnsport key public : 65
        Util.arrayCopyNonAtomic(buf, (short) (OFFSET_CDATA + 4), scratchBuffer, (short) 0, (short) 65);

        ecdh.init(transportKey.getPrivate());
        short resultLen = ecdh.generateSecret(scratchBuffer, (short) 0, (short) 65, scratchBuffer, (short) 65);
        sha256.reset();
        sha256.doFinal(scratchBuffer, (short) 65, resultLen, hashBuffer, (short) 0);
        transportKeySecret.setKey(hashBuffer, (short) 0);

        aesCBCCipher.init(transportKeySecret, Cipher.MODE_DECRYPT);

        short cipherLength = aesCBCCipher.doFinal(buf, (short) (OFFSET_CDATA + 71), (short) 32, mainBuffer, (short) 0);

        ((ECPrivateKey) masterKey.getPrivate()).setS(mainBuffer, (short) 0, cipherLength);

        // Generate Public Key from given Private Key. Uses the Key Agreement API of
        // Java card.
        // NoXY
        // ecMultiplyHelper.init(masterKey.getPrivate());
        // short publicKeyLength =
        // ecMultiplyHelper.generateSecret(Secp256k1.SECP256K1_G, (short) 0, (short) 65,
        // mainBuffer, (short) 0);
        // ((ECPublicKey) masterKey.getPublic()).setW(mainBuffer, (short) 0,
        // publicKeyLength);

        transportKey.getPrivate().clearKey();
        transportKeySecret.clearKey();
    }

    private void processExportWords(APDU apdu) {
        if (pin.isValidated() == false) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        short privateKeyLength = ((ECPrivateKey) masterKey.getPrivate()).getS(mainBuffer, (short) 0);
    }

    private void processImportWords(APDU apdu) {
        if (pin.isValidated() == false) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
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
