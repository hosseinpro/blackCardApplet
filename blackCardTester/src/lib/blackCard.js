class BlackCard {
  cardreaderTransmit = null;

  constructor(cardreaderTransmit) {
    this.cardreaderTransmit = cardreaderTransmit;
  }

  ////Begin of Utils
  parseResponseAPDU(responseAPDU) {
    responseAPDU = responseAPDU.toUpperCase();
    const data = responseAPDU.substring(0, responseAPDU.length - 4);
    const sw = responseAPDU.substring(
      responseAPDU.length - 4,
      responseAPDU.length
    );
    return { data, sw };
  }

  transmit(commandAPDU, responseFunction) {
    const cardreaderTransmit = this.cardreaderTransmit;
    return new Promise((resolve, reject) => {
      cardreaderTransmit(commandAPDU)
        .then(res => {
          const responseAPDU = this.parseResponseAPDU(res);
          if (responseAPDU.sw === "9000") {
            const result = responseFunction(responseAPDU);
            resolve(result);
          } else {
            reject({ sw: responseAPDU.sw });
          }
        })
        .catch(error => {
          reject(error);
        });
    });
  }

  hex2Ascii(hex) {
    hex = hex.toString();
    let str = "";
    for (var i = 0; i < hex.length && hex.substr(i, 2) !== "00"; i += 2)
      str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    return str;
  }

  ascii2hex(str) {
    var arr1 = [];
    for (var n = 0, l = str.length; n < l; n++) {
      var hex = Number(str.charCodeAt(n)).toString(16);
      arr1.push(hex);
    }
    return arr1.join("");
  }

  padHex(hex, numberOfDigits) {
    const str = "00000000" + hex;
    const r = str.substring(str.length - numberOfDigits);
    return r;
  }
  ////End of Utils

  ////Begin of card functions
  selectApplet() {
    const apduSelectApplect = "00 A4 04 00 06 FFBC00000001";
    return this.transmit(apduSelectApplect, responseAPDU => {
      return { result: true };
    });
  }

  getSerialNumber() {
    //ISO/IEC 7816-4 2005 Section 7.2.3
    //P1-P2: FID (2FE2: EFiccid)
    //Le=00: read entire file
    const apduGetSerialNumber = "00 B1 2F E2 00";
    return this.transmit(apduGetSerialNumber, responseAPDU => {
      return { serialNumber: responseAPDU.data };
    });
  }

  getVersion() {
    //ISO/IEC 7816-4 2005 Section 7.2.3
    //P1-P2: FID
    //Le=00: read entire file
    const apduGetVersion = "00 B1 BC 01 00";
    return this.transmit(apduGetVersion, responseAPDU => {
      const splitData = this.hex2Ascii(responseAPDU.data).split(" ");
      const type = splitData[0];
      const version = splitData[1];
      return { type, version };
    });
  }

  getLabel() {
    //ISO/IEC 7816-4 2005 Section 7.2.3
    //P1-P2: FID
    //Le=00: read entire file
    const apduGetLabel = "00 B1 BC 02 00";
    return this.transmit(apduGetLabel, responseAPDU => {
      const label = this.hex2Ascii(responseAPDU.data);
      return { label };
    });
  }

  setLabel(newLabel) {
    //ISO/IEC 7816-4 2005 Section 7.2.4
    //P1-P2: FID
    //Le=00: write entire file
    const hexLabel = this.ascii2hex(newLabel);
    const hexLabelLength = this.padHex((hexLabel.length / 2).toString(16), 2);
    const apduSetLabel = "00 D1 BC 02" + hexLabelLength + hexLabel;
    return this.transmit(apduSetLabel, responseAPDU => {
      return { result: true };
    });
  }

  verifyPIN(cardPIN) {
    //ISO/IEC 7816-4 2005 Section 7.5.6
    //P2=00: global PIN
    const apduVerifyPIN = "00 20 00 00 04" + this.ascii2hex(cardPIN);
    return this.transmit(apduVerifyPIN, responseAPDU => {
      return { result: true };
    });
  }

  changePIN(cardNewPIN) {
    //ISO/IEC 7816-4 2005 Section 7.5.7
    //p1=01: just new pin is included
    //P2=00: global PIN
    const apduChangePIN = "00 24 01 00 04" + this.ascii2hex(cardNewPIN);
    return this.transmit(apduChangePIN, responseAPDU => {
      return { result: true };
    });
  }

  setPUK(cardPUK) {
    //ISO/IEC 7816-4 2005 Section 7.5.7
    //p1=31: it's PUK and just new puk is included
    //P2=00: global PUK
    const apduSetPUK = "00 24 31 00 08" + this.ascii2hex(cardPUK);
    return this.transmit(apduSetPUK, responseAPDU => {
      return { result: true };
    });
  }

  unblockPIN(cardPUK) {
    //ISO/IEC 7816-4 2005 Section 7.5.10
    //p1=01: new pin is not included
    //P2=00: global PIN
    const apduUnblockPIN = "00 2C 01 00 08" + this.ascii2hex(cardPUK);
    return this.transmit(apduUnblockPIN, responseAPDU => {
      return { result: true };
    });
  }

  generateMasterSeed() {
    //ISO/IEC 7816-8 2004 Section 5.1
    //P1=84: key generation with no output
    //P2=01: reference to master seed
    const apduGenerateMS = "00 46 84 01";
    return this.transmit(apduGenerateMS, responseAPDU => {
      return { result: true };
    });
  }

  getAddress() {
    //ISO/IEC 7816-4 2005 Section 7.2.3
    //P1-P2: FID
    //Le=00: read entire file
    const apduGetAddress = "00 B1 BC 03 00";
    return this.transmit(apduGetAddress, responseAPDU => {
      const address = this.hex2Ascii(responseAPDU.data);
      return { address };
    });
  }

  removeMasterSeed() {
    //ISO/IEC 7816-8 2004 Section 5.1
    //P1=C4: key remove with no output (non-standard)
    //P2=01: reference to master seed
    const apduRemoveMS = "00 46 C4 01";
    return this.transmit(apduRemoveMS, responseAPDU => {
      return { result: true };
    });
  }

  //     public String signTransaction(String transaction)
  //     {
  //         //ISO/IEC 7816-8 2004 Section 5.2 and 5.4
  //         //P1=9E: digitla signature
  //         //P2=9A: plain data to be signed
  //         int transactionLength = transaction.length() / 2;
  //         String hexTransactionLength = "";
  //         if (transactionLength <= 255)
  //             //short data
  //             hexTransactionLength = String.format("%02X", transactionLength);
  //         else
  //             //extended data
  //             hexTransactionLength = "00" + String.format("%04X", transactionLength);
  //         String signTx = "00 2A 9E 9A" + hexTransactionLength + transaction + "49";//max sig len is 73 (0x49)
  //         String apduResp = transmit(signTx);
  //         if ((apduResp == null) || (!utils.getSW(apduResp).equals("9000")))
  //             return null;
  //         String signature = utils.getData(apduResp);
  //         return signature;
  //     }

  generateTransportKey() {
    //ISO/IEC 7816-8 2004 Section 5.1
    //P1=84: key generation with no output
    //P2=00: reference to transport Key
    //Lc=null and Le=256
    //just returns modulus, public exponent = 0x10001
    const apduGenerateTK = "00 46 80 00 00";
    return this.transmit(apduGenerateTK, responseAPDU => {
      const transportKeyPublic = responseAPDU.data;
      return { transportKeyPublic };
    });
  }

  importTransportKeyPublic(backupCardTransportKeyPublic) {
    //ISO/IEC 7816-4 2005 Section 7.2.4
    //P1-P2: FID
    //Le=00: write entire file
    const backupCardTransportKeyPublicLength = this.padHex(
      (backupCardTransportKeyPublic.length / 2).toString(16),
      2
    );
    const apduImportTKPub =
      "00 D1 BC 04 " +
      backupCardTransportKeyPublicLength +
      backupCardTransportKeyPublic;
    return this.transmit(apduImportTKPub, responseAPDU => {
      return { result: true };
    });
  }

  exportMasterSeed(yesCode) {
    //ISO/IEC 7816-8 2004 Section 5.2 and 5.9
    //P1=86: palin value encyption
    //P2=80: plain input data (on card)
    //Lc=len of publicKey and Le=len of encrypted data
    const apduExportMS = "00 2A 86 80 04" + this.ascii2hex(yesCode);
    return this.transmit(apduExportMS, responseAPDU => {
      const encryptedMasterSeedAndTransportKeyPublic = responseAPDU.data;
      return { encryptedMasterSeedAndTransportKeyPublic };
    });
  }

  importMasterSeed(encryptedMasterSeedAndTransportKeyPublic) {
    //ISO/IEC 7816-8 2004 Section 5.2 and 5.10
    //P1=80: plain input data (on card)
    //P2=86: palin value encyption
    //Lc=len of encrypted data and Le=null
    const encryptedMasterSeedAndTransportKeyPublicLength = this.padHex(
      (encryptedMasterSeedAndTransportKeyPublic.length / 2).toString(16),
      2
    );
    const apduImportMS =
      "00 2A 80 86 " +
      encryptedMasterSeedAndTransportKeyPublicLength +
      encryptedMasterSeedAndTransportKeyPublic;
    return this.transmit(apduImportMS, responseAPDU => {
      return { result: true };
    });
  }

  exportWords() {
    //ISO/IEC 7816-4 2005 Section 7.2.3
    //P1-P2: FID
    //Le=00: read entire file
    const apduExportWords = "00 B1 BC 05 00";
    return this.transmit(apduExportWords, responseAPDU => {
      const words = this.hex2Ascii(responseAPDU.data);
      return { words };
    });
  }

  importWords(words) {
    //ISO/IEC 7816-4 2005 Section 7.2.4
    //P1-P2: FID
    //Le=00: write entire file
    const hexWords = this.ascii2hex(words);

    const hexWordsLength = this.padHex((hexWords.length / 2).toString(16), 2);
    const apduImportWords = "00 D1 BC 05" + hexWordsLength + hexWords;
    return this.transmit(apduImportWords, responseAPDU => {
      return { result: true };
    });
  }

  //     public String test(String hexInput)
  //     {
  //         String len = String.format("%02X", (hexInput.length() / 2));
  //         String testCmd = "00 AA 00 00" + len + hexInput;
  //         String apduResp = transmit(testCmd);
  //         if ((apduResp == null) || (!utils.getSW(apduResp).equals("9000")))
  //             return "";

  //         String result = utils.getData(apduResp);
  //         return result;

  //             /*String testCmd = "00 46 84 01 00";
  //             String apduResp = transmit(testCmd);
  //             if (utils.getSW(apduResp) != "9000")
  //                 return "";

  //             String result = utils.getData(apduResp);
  //             return result;*/
  //     }

  //     public String display(String text)
  //     {
  //         if(text.length() > 128)
  //             return null;
  //         String result = transmit("00 A4 04 00 07 DD 11 22 33 44 55 66 06");
  //         result = transmit("00 D0 00 00 00");

  //         result = transmit("00 D2 00 00 00");

  //         /*String hexText = utils.unicode2hex(text);
  //         String hexTextLength = String.format("%04X", (hexText.length() / 2));

  //         String payloadLength = String.format("%02X",8 + (hexText.length() / 2));
  //         result = transmit("00 D1 00 00 " +
  //                 payloadLength +
  //                 "00 " + //Reserved
  //                 "00 " + //Coding: 00:UFT-8
  //                 "0000 " + //Start column pixel
  //                 "0000 " + //Start row pixel
  //                 hexTextLength +
  //                 hexText
  //         );*/
  //         return result;
  //     }

  ////Begin of card functions
}

export default BlackCard;
