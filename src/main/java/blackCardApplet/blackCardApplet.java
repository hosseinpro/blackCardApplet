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
    private static final short MSEED_SIZE = 64;

    private static final short CL_NONE = 0;
    private static final short CL_REMOVE_MSEED = 1;
    private static final short CL_EXPORT_MSEED = 2;
    private static final short CL_EXPORT_SUBWALLET = 3;
    private static final short CL_GENERATE_SUBWALLET = 4;
    private static final short CL_SIGN_TX = 5;

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
    private static final byte subwalletPath[] = { 'm', 44, 0, 0, 1, 0, 0 };

    private static byte[] mseed;
    private static boolean mseedInitialized;
    private ECPrivateKey signKey;
    private MessageDigest sha256;
    private Signature signature;
    private KeyAgreement ecdh;
    private AESKey transportKeySecret;
    private static KeyPair transportKey;
    private Cipher aesCBCCipher;

    private byte[] commandBuffer80;
    private short commandLock;

    private byte[] main500;
    private byte[] scratch515;

    private static Display display;
    private static BIP bip;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new blackCardApplet().register();
    }

    public blackCardApplet() {

        display = new Display();
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
        scratch515 = JCSystem.makeTransientByteArray((short) 515, JCSystem.CLEAR_ON_DESELECT);

        sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        signature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        ecdh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
        transportKeySecret = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
        aesCBCCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        commandBuffer80 = JCSystem.makeTransientByteArray((short) 80, JCSystem.CLEAR_ON_DESELECT);

        commandLock = CL_NONE;
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            display.displayWelcome(version, label, labelLength, scratch515);
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
            if ((ins == (byte) 0xB0) && (p1 == (byte) 0x2F) && (p2 == (byte) 0xE2)) {
                processGetSerialNumber(apdu);
                commandLock = CL_NONE;
            } else if ((ins == (byte) 0xB0) && (p1 == (byte) 0xBC) && (p2 == (byte) 0x01)) {
                processGetVersion(apdu);
                commandLock = CL_NONE;
            } else if ((ins == (byte) 0xB0) && (p1 == (byte) 0xBC) && (p2 == (byte) 0x02)) {
                processGetLabel(apdu);
                commandLock = CL_NONE;
            } else if ((ins == (byte) 0xD0) && (p1 == (byte) 0xBC) && (p2 == (byte) 0x02)) {
                processSetLabel(apdu);
                commandLock = CL_NONE;
            } else if ((ins == (byte) 0x20) && (p1 == (byte) 0x00) && (p2 == (byte) 0x00)) {
                processVerifyPIN(apdu);
                commandLock = CL_NONE;
            } else if ((ins == (byte) 0x24) && (p1 == (byte) 0x01) && (p2 == (byte) 0x00)) {
                processChangePIN(apdu);
                commandLock = CL_NONE;
            } else if ((ins == (byte) 0x24) && (p1 == (byte) 0x31) && (p2 == (byte) 0x00)) {
                processSetPUK(apdu);
                commandLock = CL_NONE;
            } else if ((ins == (byte) 0x2C) && (p1 == (byte) 0x01) && (p2 == (byte) 0x00)) {
                processUnblockPIN(apdu);
                commandLock = CL_NONE;
            } else if ((ins == (byte) 0xC0) && (p1 == (byte) 0xBC) && (p2 == (byte) 0x03)) {
                processGenerateMasterSeed(apdu);
                commandLock = CL_NONE;
            } else if ((ins == (byte) 0xE1) && (p1 == (byte) 0xBC) && (p2 == (byte) 0x03)) {
                processRequestRemoveMasterSeed(apdu);
                commandLock = CL_REMOVE_MSEED;
            } else if ((ins == (byte) 0xE2) && (p1 == (byte) 0xBC) && (p2 == (byte) 0x03)) {
                if (commandLock != CL_REMOVE_MSEED) {
                    ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
                }
                processRemoveMasterSeed(apdu);
                commandLock = CL_NONE;
            } else if ((ins == (byte) 0xB1) && (p1 == (byte) 0xBC) && (p2 == (byte) 0x03)) {
                processRequestExportMasterSeed(apdu);
                commandLock = CL_EXPORT_MSEED;
            } else if ((ins == (byte) 0xB2) && (p1 == (byte) 0xBC) && (p2 == (byte) 0x03)) {
                if (commandLock != CL_EXPORT_MSEED) {
                    ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
                }
                processExportMasterSeed(apdu);
                commandLock = CL_NONE;
            } else if ((ins == (byte) 0xD0) && (p1 == (byte) 0xBC) && (p2 == (byte) 0x03)) {
                processImportMasterSeed(apdu);
                commandLock = CL_NONE;
            } else if ((ins == (byte) 0xDD) && (p1 == (byte) 0xBC) && (p2 == (byte) 0x03)) {
                processImportMasterSeedPalin(apdu);
                commandLock = CL_NONE;
            } else if ((ins == (byte) 0xC0) && (p1 == (byte) 0xBC) && (p2 == (byte) 0x07)) {
                processGetAddressList(apdu);
                commandLock = CL_NONE;
            } else if ((ins == (byte) 0xC0) && (p1 == (byte) 0xBC) && (p2 == (byte) 0x08)) {
                processGetSubWalletAddressList(apdu);
                commandLock = CL_NONE;
            } else if ((ins == (byte) 0xC1) && (p1 == (byte) 0xBC) && (p2 == (byte) 0x06)) {
                processRequestGenerateSubWallet(apdu);
                commandLock = CL_GENERATE_SUBWALLET;
            } else if ((ins == (byte) 0xC2) && (p1 == (byte) 0xBC) && (p2 == (byte) 0x06)) {
                if (commandLock != CL_GENERATE_SUBWALLET) {
                    ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
                }
                processGenerateSubWallet(apdu);
                commandLock = CL_NONE;
            } else if ((ins == (byte) 0xB1) && (p1 == (byte) 0xBC) && (p2 == (byte) 0x06)) {
                processRequestExportSubWallet(apdu);
                commandLock = CL_EXPORT_SUBWALLET;
            } else if ((ins == (byte) 0xB2) && (p1 == (byte) 0xBC) && (p2 == (byte) 0x06)) {
                if (commandLock != CL_EXPORT_SUBWALLET) {
                    ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
                }
                processExportSubWallet(apdu);
                commandLock = CL_NONE;
            } else if ((ins == (byte) 0xC0) && (p1 == (byte) 0xBC) && (p2 == (byte) 0x04)) {
                processGenerateTransportKey(apdu);
                commandLock = CL_NONE;
            } else if ((ins == (byte) 0xD0) && (p1 == (byte) 0xBC) && (p2 == (byte) 0x05)) {
                processImportTransportKeyPublic(apdu);
                commandLock = CL_NONE;
            } else if ((ins == (byte) 0x31) && (p1 == (byte) 0x00) && (p2 == (byte) 0x01)) {
                processRequestSignTransaction(apdu);
                commandLock = CL_SIGN_TX;
            } else if ((ins == (byte) 0x32) && (p1 == (byte) 0x00) && (p2 == (byte) 0x01)) {
                if (commandLock != CL_SIGN_TX) {
                    ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
                }
                processSignTransaction(apdu);
                commandLock = CL_NONE;
            } else if (ins == (byte) 0xAA) {
                test(apdu);
            } else {
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

        apdu.sendBytesLong(main500, (short) 0, (short) 500);
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

    private void processRequestRemoveMasterSeed(APDU apdu) {
        if (pin.isValidated() == false) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        short offset = generateYesCode(main500, (short) 0);

        display.displayText(main500, (short) 0, offset, scratch515, (short) 0);
    }

    private short generateYesCode(byte[] yesCodeBuffer, short yesCodeOffset) {
        for (short i = 0; i < PIN_SIZE; i++) {
            do {
                randomData.generateData(yesCodeBuffer, (short) (yesCodeOffset + i), (short) 1);
            } while (yesCodeBuffer[yesCodeOffset + i] < 0);
            byte b = (byte) (yesCodeBuffer[yesCodeOffset + i] % 10);
            yesCodeBuffer[yesCodeOffset + i] = (byte) (b + 0x30);
        }
        yesCode.update(yesCodeBuffer, yesCodeOffset, PIN_SIZE);
        yesCode.resetAndUnblock();
        return PIN_SIZE;
    }

    private void verifyYesCode(byte[] yesCodeBuffer, short yesCodeOffset) {
        // if (yesCode.check(yesCodeBuffer, yesCodeOffset, PIN_SIZE) == false) {
        // ISOException.throwIt((short) (SW_PIN_INCORRECT_TRIES_LEFT |
        // yesCode.getTriesRemaining()));
        // }
        yesCode.reset();
    }

    private void processRemoveMasterSeed(APDU apdu) {
        if (pin.isValidated() == false) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        apdu.setIncomingAndReceive();
        byte[] buf = apdu.getBuffer();
        short offData = apdu.getOffsetCdata();

        verifyYesCode(buf, offData);

        Util.arrayFillNonAtomic(mseed, (short) 0, MSEED_SIZE, (byte) 0);

        mseedInitialized = false;
    }

    private void processRequestExportMasterSeed(APDU apdu) {
        if (pin.isValidated() == false) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        if (mseedInitialized == false) {
            ISOException.throwIt(SW_COMMAND_NOT_ALLOWED);
        }

        if (commandBuffer80[0] == 0x00) {
            ISOException.throwIt(SW_COMMAND_NOT_ALLOWED);
        }

        short offset = generateKCV(commandBuffer80, (short) 0, (short) 65, main500, (short) 0);

        main500[offset++] = Display.NEWLINE;

        offset += generateYesCode(main500, offset);

        display.displayText(main500, (short) 0, offset, scratch515, (short) 0);
    }

    private short createExportPacket(byte[] data, short dataOffset, short dataLen, byte[] pack, short packOffset,
            byte[] scratch64, short scratchOffset) {

        // Generate main wallet transport key
        Secp256k1.setCommonCurveParameters(((ECPrivateKey) transportKey.getPrivate()));
        Secp256k1.setCommonCurveParameters(((ECPublicKey) transportKey.getPublic()));
        transportKey.genKeyPair();

        ecdh.init(transportKey.getPrivate());
        short resultLen = ecdh.generateSecret(commandBuffer80, (short) 0, (short) 65, scratch64, scratchOffset);
        sha256.reset();
        sha256.doFinal(scratch64, scratchOffset, resultLen, scratch64, (short) (scratchOffset + resultLen));
        transportKeySecret.setKey(scratch64, (short) (scratchOffset + resultLen));

        aesCBCCipher.init(transportKeySecret, Cipher.MODE_ENCRYPT);

        // exportPacket ::= SEQUENCE {
        // ECC256PublicKey INTEGER,
        // AES256Cipher INTEGER
        // }
        pack[packOffset + 0] = (byte) 0x30;// SEQUENCE
        pack[packOffset + 1] = (byte) 0x85;// length:133
        pack[packOffset + 2] = (byte) 0x02;// INTEGER
        pack[packOffset + 3] = (byte) 0x41;// length : 65
        // mainBuffer[4..68]//ECC256PublicKey: 65 bytes
        ((ECPublicKey) transportKey.getPublic()).getW(pack, (short) (packOffset + 4));
        pack[packOffset + 69] = (byte) 0x02;// INTEGER
        pack[packOffset + 70] = (byte) 0x40;// length: 64
        // mainBuffer[71..134]//AES256Cipher: 64 bytes
        aesCBCCipher.doFinal(data, dataOffset, dataLen, pack, (short) (packOffset + 71));

        transportKey.getPrivate().clearKey();
        transportKeySecret.clearKey();

        return (short) 135;
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
        short offData = apdu.getOffsetCdata();

        verifyYesCode(buf, offData);

        short packLen = createExportPacket(mseed, (short) 0, MSEED_SIZE, main500, (short) 0, scratch515, (short) 0);

        apdu.setOutgoing();
        apdu.setOutgoingLength(packLen);
        apdu.sendBytesLong(main500, (short) 0, packLen);
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
        Util.arrayCopyNonAtomic(buf, (short) (OFFSET_CDATA + 4), scratch515, (short) 0, (short) 65);

        ecdh.init(transportKey.getPrivate());
        short resultLen = ecdh.generateSecret(scratch515, (short) 0, (short) 65, scratch515, (short) 65);
        sha256.reset();
        sha256.doFinal(scratch515, (short) 65, resultLen, scratch515, (short) (65 + resultLen));
        transportKeySecret.setKey(scratch515, (short) (65 + resultLen));

        aesCBCCipher.init(transportKeySecret, Cipher.MODE_DECRYPT);
        aesCBCCipher.doFinal(buf, (short) (OFFSET_CDATA + 71), MSEED_SIZE, mseed, (short) 0);
        mseedInitialized = true;

        transportKey.getPrivate().clearKey();
        transportKeySecret.clearKey();
    }

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
                buf[OFFSET_CDATA + 7], main500, (short) 32, scratch515, (short) 0);

        apdu.setOutgoing();
        apdu.setOutgoingLength(reslutLen);
        apdu.sendBytesLong(main500, (short) 32, reslutLen);
    }

    private void processGetSubWalletAddressList(APDU apdu) {
        if (pin.isValidated() == false) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        if (mseedInitialized == false) {
            ISOException.throwIt(SW_COMMAND_NOT_ALLOWED);
        }

        apdu.setIncomingAndReceive();
        byte[] buf = apdu.getBuffer();
        short lc = apdu.getIncomingLength();

        if (lc != (byte) 0x03) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        short numOfSub = buf[OFFSET_CDATA];
        short firstSubWalletNumber = Util.makeShort(buf[OFFSET_CDATA + 1], buf[OFFSET_CDATA + 2]);

        main500[0] = 25;
        short moffset = 1;

        for (short i = firstSubWalletNumber; i < (firstSubWalletNumber + numOfSub); i++) {

            bip.generateSubwalletSeed(mseed, (short) 0, MSEED_SIZE, i, scratch515, (short) 0, scratch515, (short) 64);

            bip.bip44DerivePath(scratch515, (short) 0, (short) 64, subwalletPath, (short) 0, scratch515, (short) 64,
                    (short) 1, scratch515, (short) 96, scratch515, (short) 121);

            moffset = Util.arrayCopyNonAtomic(scratch515, (short) 97, main500, moffset, (short) 25);
        }

    }

    private void processRequestGenerateSubWallet(APDU apdu) {
        if (pin.isValidated() == false) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        if (mseedInitialized == false) {
            ISOException.throwIt(SW_COMMAND_NOT_ALLOWED);
        }

        apdu.setIncomingAndReceive();
        byte[] buf = apdu.getBuffer();
        short lc = apdu.getIncomingLength();

        Util.arrayCopyNonAtomic(buf, OFFSET_CDATA, commandBuffer80, (short) 0, lc);

        // short spendIndex = (short) (lc); // 8B
        // short feeIndex = (short) (lc + 8); // 8B
        // short numOfSubIndex = (short) (lc + 16); // 1B
        // short firstSubKeyPathIndex = (short) (lc + 17); // 7B

        short offset = generateYesCode(main500, (short) 0);

        display.displayText(main500, (short) 0, offset, scratch515, (short) 0);
    }

    private void processGenerateSubWallet(APDU apdu) {
        if (pin.isValidated() == false) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        if (mseedInitialized == false) {
            ISOException.throwIt(SW_COMMAND_NOT_ALLOWED);
        }

        apdu.setIncomingAndReceive();
        byte[] buf = apdu.getBuffer();
        short offData = apdu.getOffsetCdata();

        verifyYesCode(buf, offData);

        // commandBuffer80
        short spendIndex = 0; // 8B
        short feeIndex = 8; // 8B
        short numOfSubIndex = 16; // 1B
        // short firstSubKeyPathIndex = 17; // 7B
        short firstSubWalletIndex = 17; // 2B

        // buf
        short fundIndex = (short) (offData + 4); // 8B
        short changeKeyPathIndex = (short) (offData + 12); // 7B
        short inputSectionIndex = (short) (offData + 19); // 1B + n*66B
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
        short numOfSub = commandBuffer80[numOfSubIndex];
        if (numOfSub > 10) {// Maximum number of sub wallets
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        short outputLength = (short) (9 + (numOfSub + 1) * 34);
        short outputIndex = (short) ((short) main500.length - outputLength);// Output length
        moffset = outputIndex;
        main500[moffset++] = (byte) (numOfSub + 1);

        short firstSubWalletNumber = Util.makeShort(commandBuffer80[firstSubWalletIndex],
                commandBuffer80[firstSubWalletIndex + 1]);

        // Calculate subwallet addresses
        // bip.bip44DerivePath(mseed, (short) 0, MSEED_SIZE, commandBuffer80,
        // firstSubKeyPathIndex, scratch515, (short) 0,
        // numOfSub, scratch515, (short) 32, scratch515, (short) 283);// 32 + 1 +
        // numOfSub * 25 => for max numOfSub
        // // = 283
        // short subwalletAddressIndex = 33;

        // shared = spend / numOfSub
        MathMod256.div(scratch515, (short) 0, commandBuffer80, spendIndex, (byte) numOfSub, (short) 8);

        // for (short i = 0; i < numOfSub; i++) {
        for (short i = firstSubWalletNumber; i < (firstSubWalletNumber + numOfSub); i++) {
            // spend value (big endian)
            moffset = toBigEndian(scratch515, (short) 0, main500, moffset, (short) 8);

            bip.generateSubwalletSeed(mseed, (short) 0, MSEED_SIZE, i, scratch515, (short) 8, scratch515, (short) 72);

            bip.bip44DerivePath(scratch515, (short) 8, (short) 64, subwalletPath, (short) 0, scratch515, (short) 72,
                    (short) 1, scratch515, (short) 104, scratch515, (short) 130);

            // P2SH dest pub key hash
            Util.arrayCopyNonAtomic(scratch515, (short) 105/* (subwalletAddressIndex + 1) */, P2PKH, (short) 4,
                    (short) 20);
            moffset = Util.arrayCopyNonAtomic(P2PKH, (short) 0, main500, moffset, (short) (P2PKH.length));
            // subwalletAddressIndex += 25;
        }
        // change value (big endian) : change = fund - spend - fee;
        MathMod256.sub(scratch515, (short) 0, buf, fundIndex, commandBuffer80, spendIndex, (short) 8);
        MathMod256.sub(scratch515, (short) 0, scratch515, (short) 0, commandBuffer80, feeIndex, (short) 8);
        moffset = toBigEndian(scratch515, (short) 0, main500, moffset, (short) 8);
        // P2SH change pub key hash
        bip.bip44DerivePath(mseed, (short) 0, MSEED_SIZE, buf, changeKeyPathIndex, scratch515, (short) 0, (short) 1,
                scratch515, (short) 32, scratch515, (short) 60);
        // addressList: 1B len + 25B address
        Util.arrayCopyNonAtomic(scratch515, (short) (32 + 1 + 1), P2PKH, (short) 4, (short) 20);
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

        moffset = 5;// begin of inputs
        // for (...)
        // 32B hash + 4B UTXO
        moffset = Util.arrayCopyNonAtomic(buf, (short) (inputSectionIndex + 1), main500, moffset, (short) 36);

        sha256.reset();
        sha256.update(main500, (short) 0, (short) 4);
        sha256.update(buf, inputSectionIndex, (short) (1 + 66));
        sha256.doFinal(main500, outputIndex, outputLength, scratch515, (short) 0);
        // hold tx hash in scratch 0..31

        bip.bip44DerivePath(mseed, (short) 0, MSEED_SIZE, buf, signerKeyPathsIndex, scratch515, (short) 32, (short) 1,
                scratch515, (short) 64, scratch515, (short) 90);// hold prikey in scratch 32..63 [32]

        Secp256k1.setCommonCurveParameters(signKey);
        signKey.setS(scratch515, (short) 32, (short) 32);
        signature.init(signKey, Signature.MODE_SIGN);
        short scriptLenIndex = moffset;
        moffset++;// 1B script Len
        short signatureLen = signature.sign(scratch515, (short) 0, (short) 32, main500, (short) (moffset + 1));
        main500[moffset] = (byte) (signatureLen + 1);// sig len + 1
        moffset += signatureLen + 1;
        main500[moffset++] = 0x01;// hash type
        short pubKeyLen = bip.ec256PrivateKeyToPublicKey(scratch515, (short) 32, main500, (short) (moffset + 1), true);
        main500[moffset++] = (byte) pubKeyLen;
        moffset += pubKeyLen;
        // x = 1B [sig len byte] + sigLen + 1B [hash type] + 1B [pubkey Len] + pubKeyLen
        main500[scriptLenIndex] = (byte) (3 + signatureLen + pubKeyLen);
        // 63 = 1B len + 32B hash + 4B UTXO + 26B script
        moffset = Util.arrayCopyNonAtomic(buf, (short) (inputSectionIndex + 63), main500, moffset, (short) 4);// sequence
        // end for

        moffset = Util.arrayCopyNonAtomic(main500, outputIndex, main500, moffset, (short) (outputLength - 4));

        apdu.setOutgoing();
        apdu.setOutgoingLength(moffset);
        apdu.sendBytesLong(main500, (short) 0, moffset);
    }

    private void processRequestExportSubWallet(APDU apdu) {
        if (pin.isValidated() == false) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        if (mseedInitialized == false) {
            ISOException.throwIt(SW_COMMAND_NOT_ALLOWED);
        }

        apdu.setIncomingAndReceive();
        byte[] buf = apdu.getBuffer();
        short lc = apdu.getIncomingLength();

        if (lc != 2) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        Util.arrayCopyNonAtomic(buf, OFFSET_CDATA, commandBuffer80, (short) 70, lc);

        short offset = generateKCV(commandBuffer80, (short) 0, (short) 65, main500, (short) 0);

        main500[offset++] = Display.NEWLINE;

        offset = Util.arrayCopyNonAtomic(commandBuffer80, (short) 70, main500, offset, lc);

        main500[offset++] = Display.NEWLINE;

        offset += generateYesCode(main500, offset);

        display.displayText(main500, (short) 0, offset, scratch515, (short) 0);
    }

    private void processExportSubWallet(APDU apdu) {
        if (pin.isValidated() == false) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        if (mseedInitialized == false) {
            ISOException.throwIt(SW_COMMAND_NOT_ALLOWED);
        }

        apdu.setIncomingAndReceive();
        byte[] buf = apdu.getBuffer();
        short offData = apdu.getOffsetCdata();

        verifyYesCode(buf, offData);

        short subWalletNumber = Util.makeShort(commandBuffer80[70], commandBuffer80[71]);

        bip.generateSubwalletSeed(mseed, (short) 0, MSEED_SIZE, subWalletNumber, scratch515, (short) 0, scratch515,
                (short) 64);

        bip.bip44DerivePath(scratch515, (short) 0, (short) 64, subwalletPath, (short) 0, scratch515, (short) 64,
                (short) 1, scratch515, (short) 96, scratch515, (short) 121);

        short packLen = createExportPacket(scratch515, (short) 64, (short) 32, main500, (short) 0, scratch515,
                (short) 96);

        apdu.setOutgoing();
        apdu.setOutgoingLength(packLen);
        apdu.sendBytesLong(main500, (short) 0, packLen);
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

        display.displayText(main500, publicKeyLength, kcvLen, scratch515, (short) 0);

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

        // Get trnsport key public : publicKeyLength = lc = 65
        Util.arrayCopyNonAtomic(buf, OFFSET_CDATA, commandBuffer80, (short) 0, (publicKeyLength));
    }

    private short toBigEndian(byte[] leNumber, short leNumberOffset, byte[] beNumber, short beNumberOffset,
            short length) {
        for (short i = 0; i < length; i++) {
            beNumber[beNumberOffset + length - 1 - i] = leNumber[leNumberOffset + i];
        }
        return (short) (beNumberOffset + length);
    }

    private short signTransaction(byte[] inputSection, short inputSectionOffset, byte[] signerKeyPaths,
            short signerKeyPathsOffset, byte[] outputSection, short outputSectionOffset, short outputSectionLength,
            byte[] signedTx, short signedTxOffset, byte[] scratch322, short scratchOffset) {
        // version 01000000
        short signedTxIndex = signedTxOffset;
        short headerIndex = signedTxIndex;
        signedTx[signedTxIndex++] = 0x01;
        signedTx[signedTxIndex++] = 0x00;
        signedTx[signedTxIndex++] = 0x00;
        signedTx[signedTxIndex++] = 0x00;
        // inputs
        signedTx[signedTxIndex++] = inputSection[inputSectionOffset]; // input count

        // output and footer
        short footerIndex = (short) (signedTx.length - (outputSectionLength + 8));
        signedTxIndex = Util.arrayCopyNonAtomic(outputSection, outputSectionOffset, signedTx, footerIndex,
                outputSectionLength);
        // locktime 00000000
        signedTx[signedTxIndex++] = 0x00;
        signedTx[signedTxIndex++] = 0x00;
        signedTx[signedTxIndex++] = 0x00;
        signedTx[signedTxIndex++] = 0x00;
        // hashtype 01000000
        signedTx[signedTxIndex++] = 0x01;
        signedTx[signedTxIndex++] = 0x00;
        signedTx[signedTxIndex++] = 0x00;
        signedTx[signedTxIndex++] = 0x00;

        short offset = scratchOffset;

        signedTxIndex = (short) (headerIndex + 5);// begin of outputs
        // for (...)
        // 32B hash + 4B UTXO
        signedTxIndex = Util.arrayCopyNonAtomic(inputSection, (short) (inputSectionOffset + 1), signedTx, signedTxIndex,
                (short) 36);

        sha256.reset();
        sha256.update(signedTx, headerIndex, (short) 5);// header
        sha256.update(inputSection, (short) (inputSectionOffset + 1), (short) 66);// inputs
        sha256.doFinal(signedTx, footerIndex, (short) (outputSectionLength + 8), scratch322, offset);// footer
        // hold tx hash in scratch 0..31

        bip.bip44DerivePath(mseed, (short) 0, MSEED_SIZE, signerKeyPaths, signerKeyPathsOffset, scratch322,
                (short) (offset + 32), (short) 1, scratch322, (short) (offset + 64), scratch322, (short) (offset + 90));
        // hold prikey in scratch 32..63 [32]

        Secp256k1.setCommonCurveParameters(signKey);
        signKey.setS(scratch322, (short) (offset + 32), (short) 32);
        signature.init(signKey, Signature.MODE_SIGN);
        short scriptLenIndex = signedTxIndex;
        signedTxIndex++;// 1B script Len
        short signatureLen = 0;
        short sIndex = 0;
        do {
            signatureLen = signature.sign(scratch322, (short) (offset), (short) 32, scratch322, (short) (offset + 64));
            // 30 45 02 20 XXXX 02 20 XXXX
            sIndex = (short) (offset + 64 + 4 - 1);
            sIndex += scratch322[sIndex];
            sIndex += 3;
            if (scratch322[sIndex] == 0x00) {
                sIndex++;
            }
            // if s > N/2
        } while (MathMod256.ucmp(scratch322, sIndex, Secp256k1.SECP256K1_Rdiv2, (short) 0,
                (short) Secp256k1.SECP256K1_Rdiv2.length) > 0);

        Util.arrayCopyNonAtomic(scratch322, (short) (offset + 64), signedTx, (short) (signedTxIndex + 1), signatureLen);

        signedTx[signedTxIndex] = (byte) (signatureLen + 1);// sig len + 1
        signedTxIndex += signatureLen + 1;
        signedTx[signedTxIndex++] = 0x01;// hash type
        short pubKeyLen = bip.ec256PrivateKeyToPublicKey(scratch322, (short) (offset + 32), signedTx,
                (short) (signedTxIndex + 1), true);
        signedTx[signedTxIndex++] = (byte) pubKeyLen;
        signedTxIndex += pubKeyLen;
        // x = 1B [sig len byte] + sigLen + 1B [hash type] + 1B [pubkey Len] + pubKeyLen
        signedTx[scriptLenIndex] = (byte) (3 + signatureLen + pubKeyLen);
        // 63 = 1B len + 32B hash + 4B UTXO + 26B script
        signedTxIndex = Util.arrayCopyNonAtomic(inputSection, (short) (inputSectionOffset + 63), signedTx,
                signedTxIndex, (short) 4);// sequence
        // end for

        signedTxIndex = Util.arrayCopyNonAtomic(signedTx, footerIndex, signedTx, signedTxIndex,
                (short) (outputSectionLength + 4));

        short signedTxLength = (short) (signedTxIndex - outputSectionOffset - outputSectionLength - 1);
        return signedTxLength;
    }

    private void processRequestSignTransaction(APDU apdu) {
        if (pin.isValidated() == false) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        if (mseedInitialized == false) {
            ISOException.throwIt(SW_COMMAND_NOT_ALLOWED);
        }

        apdu.setIncomingAndReceive();
        byte[] buf = apdu.getBuffer();
        short lc = apdu.getIncomingLength();

        Util.arrayCopyNonAtomic(buf, OFFSET_CDATA, commandBuffer80, (short) 0, lc);

        // short spendIndex = OFFSET_CDATA + 0; // 8B
        // short feeIndex = OFFSET_CDATA + 8; // 8B
        // short destAddressIndex = OFFSET_CDATA + 16; // 25B
    }

    private void processSignTransaction(APDU apdu) {
        apdu.setIncomingAndReceive();
        byte[] buf = apdu.getBuffer();
        short offData = apdu.getOffsetCdata();

        verifyYesCode(buf, offData);

        // commandBuffer80
        short spendIndex = 0; // 8B
        short feeIndex = 8; // 8B
        short destAddressIndex = 16; // 25B

        // buf
        short fundIndex = (short) (offData + 4); // 8B
        short changeKeyPathIndex = (short) (offData + 12); // 7B
        short inputSectionIndex = (short) (offData + 19); // 1B + n*66B
        short inputCount = buf[inputSectionIndex];
        short signerKeyPathsIndex = (short) (inputSectionIndex + 1 + (short) (inputCount * 66)); // n*7B

        // build output section
        short moffset = 0;
        main500[moffset++] = 0x02;
        // spend value (big endian)
        moffset = toBigEndian(commandBuffer80, spendIndex, main500, moffset, (short) 8);
        // P2SH dest pub key hash
        Util.arrayCopyNonAtomic(commandBuffer80, (short) (destAddressIndex + 1), P2PKH, (short) 4, (short) 20);
        moffset = Util.arrayCopyNonAtomic(P2PKH, (short) 0, main500, moffset, (short) (P2PKH.length));
        // change value (big endian) : change = fund - spend - fee;
        MathMod256.sub(scratch515, (short) 0, buf, fundIndex, commandBuffer80, spendIndex, (short) 8);
        MathMod256.sub(scratch515, (short) 0, scratch515, (short) 0, commandBuffer80, feeIndex, (short) 8);
        moffset = toBigEndian(scratch515, (short) 0, main500, moffset, (short) 8);
        // P2SH change pub key hash
        bip.bip44DerivePath(mseed, (short) 0, MSEED_SIZE, buf, changeKeyPathIndex, scratch515, (short) 0, (short) 1,
                scratch515, (short) 32, scratch515, (short) 60);
        // addressList: 1B len + 25B address
        Util.arrayCopyNonAtomic(scratch515, (short) (32 + 1 + 1), P2PKH, (short) 4, (short) 20);
        moffset = Util.arrayCopyNonAtomic(P2PKH, (short) 0, main500, moffset, (short) (P2PKH.length));

        // build final Tx
        short signedTxLength = signTransaction(buf, inputSectionIndex, buf, signerKeyPathsIndex, main500, (short) 0,
                (short) 69, main500, (short) 70, scratch515, (short) 0);

        apdu.setOutgoing();
        apdu.setOutgoingLength(signedTxLength);
        apdu.sendBytesLong(main500, (short) 70, signedTxLength);
    }

    private short generateKCV(byte[] inBubber, short inOffset, short inLength, byte[] outBuffer, short outOffset) {
        sha256.reset();
        short sha256Len = sha256.doFinal(inBubber, inOffset, inLength, scratch515, (short) 0);

        Ripemd160.hash32(scratch515, (short) 0, scratch515, sha256Len, scratch515, (short) 60);
        short ripemd160Len = (short) 20;

        short b58Len = Base58.encode(scratch515, sha256Len, ripemd160Len, outBuffer, outOffset, scratch515, (short) 60);

        return b58Len;
    }
}
