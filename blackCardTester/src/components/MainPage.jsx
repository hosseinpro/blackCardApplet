import React, { Component } from "react";

import SmartcardBridgeClient from "../lib/smartcardBridgeClient";
import BlackCard from "../lib/blackCard";

class MainPage extends Component {
  constructor(props) {
    super();
    this.state.smartcardBridgeClient = new SmartcardBridgeClient(
      props.smartcardBridgeAddress
    );
  }

  state = {
    smartcardBridgeClient: null,
    blackCard: null,
    osName: "",
    isSmartcardBridgeAvailable: false,
    cardreaderList: [],
    selectedCardreader: "",
    isSmartcardConnected: false,
    protocol: 0,
    errorMessage: "",
    responseAPDULog: ""
  };

  componentDidMount() {
    window.addEventListener("beforeunload", this.componentCleanup.bind(this));
    this.setState({ osName: this.getOSName() });
    this.state.smartcardBridgeClient
      .getVersion()
      .then(res => {
        this.setState({ isSmartcardBridgeAvailable: true });
        this.state.smartcardBridgeClient
          .listCardreaders()
          .then(cardreaderList => {
            const selectedCardreader = cardreaderList[0];
            this.setState({ cardreaderList, selectedCardreader });
          })
          .catch(error => {
            this.setState({ errorMessage: error });
          });
      })
      .catch(error => {
        console.log(error);
        this.setState({ isSmartcardBridgeAvailable: false });
      });
  }

  componentCleanup() {
    this.state.smartcardBridgeClient
      .cardreaderDisconnect(this.state.selectedCardreader)
      .then(res => {
        this.setState({
          isSmartcardConnected: false,
          errorMessage: null
        });
      })
      .catch(error => {
        this.setState({ errorMessage: error });
      });
  }

  componentWillUnmount() {
    this.componentCleanup();
    window.removeEventListener("beforeunload", this.componentCleanup);
  }

  getOSName() {
    let OSName = "";
    if (navigator.appVersion.indexOf("Win") !== -1) OSName = "Windows";
    if (navigator.appVersion.indexOf("Mac") !== -1) OSName = "MacOS";
    if (navigator.appVersion.indexOf("Linux") !== -1) OSName = "Linux";
    if (navigator.appVersion.indexOf("X11") !== -1) OSName = "UNIX";
    return OSName;
  }

  onChangeCardreaderList(e) {
    this.state.smartcardBridgeClient.cardreaderDisconnect(
      this.state.selectedCardreader
    );
    this.setState({
      selectedCardreader: e.target.value,
      isSmartcardConnected: false
    });
  }

  onClickConnectDisconnect() {
    if (this.state.isSmartcardConnected) {
      this.state.smartcardBridgeClient
        .cardreaderDisconnect(this.state.selectedCardreader)
        .then(res => {
          this.setState({
            isSmartcardConnected: false,
            errorMessage: null
          });
        })
        .catch(error => {
          this.setState({ errorMessage: error });
        });
    } else {
      this.state.smartcardBridgeClient
        .cardreaderConnect(this.state.selectedCardreader)
        .then(res => {
          this.setState({
            isSmartcardConnected: true,
            protocol: res.protocol,
            errorMessage: null
          });
          this.setState({
            blackCard: new BlackCard(this.cardreaderTransmit.bind(this))
          });
        })
        .catch(error => {
          this.setState({ errorMessage: error });
        });
    }
  }

  getTime() {
    const now = new Date();
    let hour = "" + now.getHours();
    if (hour.length === 1) {
      hour = "0" + hour;
    }
    let minute = "" + now.getMinutes();
    if (minute.length === 1) {
      minute = "0" + minute;
    }
    let second = "" + now.getSeconds();
    if (second.length === 1) {
      second = "0" + second;
    }
    let millisecond = "" + now.getMilliseconds();
    if (millisecond.length === 1) {
      millisecond = "00" + millisecond;
    }
    if (millisecond.length === 2) {
      millisecond = "0" + millisecond;
    }
    return hour + ":" + minute + ":" + second + "." + millisecond;
  }

  cardreaderTransmit(commandAPDU) {
    commandAPDU = commandAPDU.toUpperCase();
    return new Promise((resolve, reject) => {
      const timeCommand = this.getTime();
      const responseAPDULog =
        this.state.responseAPDULog + timeCommand + " << " + commandAPDU + "\n";
      this.setState({
        responseAPDULog
      });
      this.outputResponseAPDULog.scrollTop = this.outputResponseAPDULog.scrollHeight;
      this.state.smartcardBridgeClient
        .cardreaderTransmit(
          this.state.selectedCardreader,
          this.state.protocol,
          commandAPDU
        )
        .then(responseAPDU => {
          const timeResponse = this.getTime();
          const responseAPDULog =
            this.state.responseAPDULog +
            timeResponse +
            " >> " +
            responseAPDU +
            "\n";
          this.setState({
            responseAPDULog
          });
          this.outputResponseAPDULog.scrollTop = this.outputResponseAPDULog.scrollHeight;
          resolve(responseAPDU);
        })
        .catch(error => {
          this.setState({ errorMessage: error });
          reject(error);
        });
    });
  }

  onClickSelectApplet(e) {
    this.state.blackCard
      .selectApplet()
      .then(() => {
        this.state.blackCard
          .getSerialNumber()
          .then(res => {
            this.outputCardInfo.value = "SN: " + res.serialNumber;
            this.state.blackCard
              .getVersion()
              .then(res => {
                this.outputCardInfo.value +=
                  " | Type: " + res.type + " | Version: " + res.version;
              })
              .catch(error => {});
          })
          .catch(error => {
            console.log(error);
          });
      })
      .catch(err => {
        console.log(err);
      });
  }

  onClickPerso(e) {
    this.state.blackCard
      .setPUK(this.inputPUK.value)
      .then(res => {})
      .catch(err => {
        console.log(err);
      });
  }

  onClickVerifyPIN(e) {
    this.state.blackCard
      .verifyPIN(this.inputPIN.value)
      .then(res => {})
      .catch(err => {
        console.log(err);
      });
  }

  onClickChangePIN(e) {
    this.state.blackCard
      .changePIN(this.inputPIN.value)
      .then(res => {})
      .catch(err => {
        console.log(err);
      });
  }

  onClickUnblockPIN(e) {
    this.state.blackCard
      .unblockPIN(this.inputPIN.value)
      .then(res => {})
      .catch(err => {
        console.log(err);
      });
  }

  onClickGetLabel(e) {
    this.state.blackCard
      .getLabel()
      .then(res => {
        this.inputLabel.value = res.label;
      })
      .catch(err => {
        console.log(err);
      });
  }

  onClickSetLabel(e) {
    this.state.blackCard
      .setLabel(this.inputLabel.value)
      .then(res => {})
      .catch(err => {
        console.log(err);
      });
  }

  onClickGenMasterSeed(e) {
    this.state.blackCard
      .generateMasterSeed()
      .then(res => {
        this.outputAddress.value = "";
      })
      .catch(err => {
        console.log(err);
      });
  }

  onClickGetAddress(e) {
    this.state.blackCard
      .getAddress()
      .then(res => {
        this.outputAddress.value = res.address;
      })
      .catch(err => {
        console.log(err);
      });
  }

  onClickRemMasterSeed(e) {
    this.state.blackCard
      .removeMasterSeed()
      .then(res => {
        this.outputAddress.value = "";
      })
      .catch(err => {
        console.log(err);
      });
  }

  onClickGenTransportKey(e) {
    this.state.blackCard
      .generateTransportKey()
      .then(res => {
        this.outputTransportKeyPublic.value = res.transportKeyPublic;
      })
      .catch(err => {
        console.log(err);
      });
  }

  onClickImportTransportKey(e) {
    this.state.blackCard
      .importTransportKeyPublic(this.outputTransportKeyPublic.value)
      .then(res => {})
      .catch(err => {
        console.log(err);
      });
  }

  onClickExportMasterSeed(e) {
    this.state.blackCard
      .exportMasterSeed(this.inputOutputYesCode.value)
      .then(res => {
        this.inputOutputEncryptedMasterSeed.value =
          res.encryptedMasterSeedAndTransportKeyPublic;
      })
      .catch(err => {
        console.log(err);
      });
  }

  onClickImportMasterSeed(e) {
    this.state.blackCard
      .importMasterSeed(this.inputOutputEncryptedMasterSeed.value)
      .then(res => {})
      .catch(err => {
        console.log(err);
      });
  }

  onClickExportWords(e) {
    this.state.blackCard
      .exportWords()
      .then(res => {
        this.inputOutputWords.value = res.words;
      })
      .catch(err => {
        console.log(err);
      });
  }

  onClickImportWords(e) {
    this.state.blackCard
      .importWords(this.inputOutputWords.value)
      .then(res => {})
      .catch(err => {
        console.log(err);
      });
  }

  onClickSignTx(e) {
    // long fund = btc2satoshi(10);//from webservice
    // long spend = btc2satoshi(1);//from user
    // int txSize = 226;
    // int feeRate = 5; // satoshi/byte
    // long fee = txSize * feeRate;
    // long change = fund - spend - fee;
    // String preTxHash = "071188b73ca5dafb1aeb384cb834dfd8bbd56bf0436c4c6b01ed08a852da7e9d";//from webservice
    // int UTXOindex = 0;//from webservice
    // String hashSignerPubKey = "7534ed3da28dc41d93903b33c92833fe0c339e9a";//extract from webservice response
    // String hashSpendPubKey = "3c88aa4c355a9468fa2d35f02fdf6e8cda71e55d";//from user
    // String hashChangePubKey = hashSignerPubKey;//same as signer until HD
    // String version = "01000000";
    // int inputCount = 1;
    // String[] inputPreTxHash = new String[inputCount];
    // String[] inputUTXOindex = new String[inputCount];
    // String[] inputScript = new String[inputCount];
    // String[] inputSequence = new String[inputCount];
    // //for inputCount
    // inputPreTxHash[0] = preTxHash;
    // inputUTXOindex[0] = String.format("%08X", UTXOindex);
    // inputScript[0] = "1976a914" + hashSignerPubKey + "88ac";
    // inputSequence[0] = "ffffffff";
    // String outputCount = "02";
    // String spendValue = String.format("%016X", Long.reverseBytes(spend));
    // String spendScript = "1976a914" + hashSpendPubKey + "88ac";
    // String changeValue = String.format("%016X", Long.reverseBytes(change));
    // String changeScript = "1976a914" + hashChangePubKey + "88ac";
    // String lockTime = "00000000";
    // String unknown = "01000000";
    // String toSignTx =
    //         version +
    //         String.format("%02X", inputCount);
    // for(int i=0 ; i<inputCount ; i++)
    // {
    //     toSignTx += inputPreTxHash[i] +
    //             inputUTXOindex[i] +
    //             inputScript[i] +
    //             inputSequence[i];
    // }
    // toSignTx +=
    //         outputCount +
    //         spendValue +
    //         spendScript +
    //         changeValue +
    //         changeScript +
    //         lockTime +
    //         unknown;
    // //txtSignedTX.setText(toSignTx);
    // //String signedTx = bluecard.signTransaction(toSignTx);
    // String signedTx = bluecard.test(toSignTx);
    // txtSignedTX.setText(signedTx);
  }

  //   long btc2satoshi(long btc) {
  //     return btc * 100000000;
  // }

  // long satoshi2btc(long satoshi){
  //     return satoshi / 100000000;
  // }

  onClickTransmit(e) {
    this.cardreaderTransmit(this.inputCommandAPDU.value);
  }

  onClickClear(e) {
    this.setState({ responseAPDULog: "" });
  }

  render() {
    return (
      <div className="form-group">
        <div className="row col-xs-12">
          <div className="row mt-2 input-group">
            <label
              className="text-auto"
              hidden={this.state.isSmartcardBridgeAvailable ? false : true}
            >
              smartcardBridge is connected.
            </label>
            <div
              className="input-group"
              hidden={this.state.isSmartcardBridgeAvailable ? true : false}
            >
              <label className="text-danger form-control">
                {this.state.osName === "Windows" ||
                this.state.osName === "MacOS"
                  ? "You must download and install smartcardBridge at first. You may receive security alert because smartcardBridge is not digitally signed."
                  : "Your operating system (" +
                    this.state.osName +
                    ") is not supported."}
              </label>
              <div className="input-group-append">
                <a
                  hidden={
                    this.state.osName !== "Windows" &&
                    this.state.osName !== "MacOS"
                      ? true
                      : false
                  }
                  className="btn btn-danger"
                  href={
                    this.state.osName === "Windows"
                      ? "https://github.com/hosseinpro/smartcardPage/releases/download/v1.1.0/smartcardbridge-1.1.0.Setup.exe"
                      : this.state.osName === "MacOS"
                        ? "https://github.com/hosseinpro/smartcardPage/releases/download/v1.1.0/smartcardbridge-darwin-x64-1.1.0.zip"
                        : ""
                  }
                  role="button"
                >
                  Download
                </a>
              </div>
            </div>
          </div>
          <div className="row mt-2 input-group">
            <select
              className="custom-select"
              disabled={!this.state.isSmartcardBridgeAvailable ? true : false}
              onChange={this.onChangeCardreaderList.bind(this)}
            >
              {this.state.cardreaderList.map(readername => {
                return <option key={readername}>{readername}</option>;
              })}
            </select>
            <div className="input-group-append">
              <button
                className="btn btn-primary"
                disabled={!this.state.isSmartcardBridgeAvailable ? true : false}
                onClick={this.onClickConnectDisconnect.bind(this)}
              >
                {!this.state.isSmartcardConnected ? "Connect" : "Disconnect"}
              </button>
            </div>
          </div>
          <div className="row mt-2 input-group">
            <input
              type="text"
              className="form-control"
              placeholder="Card info"
              ref={el => (this.outputCardInfo = el)}
              readOnly
            />
            <div className="input-group-append">
              <button
                className="btn btn-primary"
                onClick={this.onClickSelectApplet.bind(this)}
                disabled={!this.state.isSmartcardConnected}
              >
                SelectApplet
              </button>
            </div>
          </div>
          <div className="row mt-2 input-group">
            <input
              type="text"
              className="form-control"
              placeholder="PUK"
              ref={el => (this.inputPUK = el)}
              disabled={!this.state.isSmartcardConnected}
            />
            <div className="input-group-append">
              <button
                className="btn btn-primary"
                onClick={this.onClickPerso.bind(this)}
                disabled={!this.state.isSmartcardConnected}
              >
                Perso
              </button>
            </div>
          </div>
          <div className="row mt-2 input-group">
            <input
              type="text"
              className="form-control"
              placeholder="PIN or PUK"
              ref={el => (this.inputPIN = el)}
              disabled={!this.state.isSmartcardConnected}
            />
            <div className="input-group-append">
              <button
                className="btn btn-primary"
                onClick={this.onClickVerifyPIN.bind(this)}
                disabled={!this.state.isSmartcardConnected}
              >
                VerifyPIN
              </button>
              <button
                className="btn btn-primary"
                onClick={this.onClickChangePIN.bind(this)}
                disabled={!this.state.isSmartcardConnected}
              >
                ChangePIN
              </button>
              <button
                className="btn btn-primary"
                onClick={this.onClickUnblockPIN.bind(this)}
                disabled={!this.state.isSmartcardConnected}
              >
                UnblockPIN
              </button>
            </div>
          </div>
          <div className="row mt-2 input-group">
            <input
              type="text"
              className="form-control"
              placeholder="Label"
              ref={el => (this.inputLabel = el)}
              disabled={!this.state.isSmartcardConnected}
            />
            <div className="input-group-append">
              <button
                className="btn btn-primary"
                onClick={this.onClickGetLabel.bind(this)}
                disabled={!this.state.isSmartcardConnected}
              >
                GetLabel
              </button>
              <button
                className="btn btn-primary"
                onClick={this.onClickSetLabel.bind(this)}
                disabled={!this.state.isSmartcardConnected}
              >
                SetLabel
              </button>
            </div>
          </div>
          <div className="row mt-2 input-group">
            <input
              type="text"
              className="form-control"
              placeholder="Address"
              ref={el => (this.outputAddress = el)}
              disabled={!this.state.isSmartcardConnected}
              readOnly
            />
            <div className="input-group-append">
              <button
                className="btn btn-primary"
                onClick={this.onClickGenMasterSeed.bind(this)}
                disabled={!this.state.isSmartcardConnected}
              >
                GenMasterSeed
              </button>
              <button
                className="btn btn-primary"
                onClick={this.onClickGetAddress.bind(this)}
                disabled={!this.state.isSmartcardConnected}
              >
                GetAddress
              </button>
              <button
                className="btn btn-primary"
                onClick={this.onClickRemMasterSeed.bind(this)}
                disabled={!this.state.isSmartcardConnected}
              >
                RemMasterSeed
              </button>
            </div>
          </div>
          <div className="row mt-2 input-group">
            <input
              type="text"
              className="form-control"
              placeholder="Transport Key public part"
              ref={el => (this.outputTransportKeyPublic = el)}
              disabled={!this.state.isSmartcardConnected}
            />
            <div className="input-group-append">
              <button
                className="btn btn-primary"
                onClick={this.onClickGenTransportKey.bind(this)}
                disabled={!this.state.isSmartcardConnected}
              >
                GenTransportKey
              </button>
              <button
                className="btn btn-primary"
                onClick={this.onClickImportTransportKey.bind(this)}
                disabled={!this.state.isSmartcardConnected}
              >
                ImportTransportKey
              </button>
            </div>
          </div>
          <div className="row mt-2 input-group">
            <input
              type="text"
              className="form-control"
              placeholder="Yes code"
              ref={el => (this.inputOutputYesCode = el)}
              disabled={!this.state.isSmartcardConnected}
            />
            <div className="input-group-append">
              <button
                className="btn btn-primary"
                onClick={this.onClickExportMasterSeed.bind(this)}
                disabled={!this.state.isSmartcardConnected}
              >
                ExportMasterSeed
              </button>
            </div>
          </div>
          <div className="row mt-2 input-group">
            <input
              type="text"
              className="form-control"
              placeholder="Encrypted Master Key and Transport Key Public"
              ref={el => (this.inputOutputEncryptedMasterSeed = el)}
              disabled={!this.state.isSmartcardConnected}
            />
            <div className="input-group-append">
              <button
                className="btn btn-primary"
                onClick={this.onClickImportMasterSeed.bind(this)}
                disabled={!this.state.isSmartcardConnected}
              >
                ImportMasterSeed
              </button>
            </div>
          </div>
          <div className="row mt-2 input-group">
            <input
              type="text"
              className="form-control"
              placeholder="Words"
              ref={el => (this.inputOutputWords = el)}
              disabled={!this.state.isSmartcardConnected}
            />
            <div className="input-group-append">
              <button
                className="btn btn-primary"
                onClick={this.onClickExportWords.bind(this)}
                disabled={!this.state.isSmartcardConnected}
              >
                ExportWords
              </button>
              <button
                className="btn btn-primary"
                onClick={this.onClickImportWords.bind(this)}
                disabled={!this.state.isSmartcardConnected}
              >
                ImportWords
              </button>
            </div>
          </div>
          <div className="row mt-2 input-group">
            <input
              type="text"
              className="form-control"
              placeholder="Tx"
              ref={el => (this.inputTx = el)}
              disabled={!this.state.isSmartcardConnected}
            />
            <div className="input-group-append">
              <button
                className="btn btn-primary"
                onClick={this.onClickSignTx.bind(this)}
                disabled={!this.state.isSmartcardConnected}
              >
                SignTX
              </button>
            </div>
          </div>
          <div className="row mt-2 input-group">
            <input
              type="text"
              className="form-control"
              ref={el => (this.inputCommandAPDU = el)}
              disabled={!this.state.isSmartcardConnected}
              placeholder="APDU"
            />
            <div className="input-group-append">
              <button
                className="btn btn-primary"
                onClick={this.onClickTransmit.bind(this)}
                disabled={!this.state.isSmartcardConnected}
              >
                Transmit
              </button>
            </div>
          </div>
          <div className="row mt-2" hidden={!this.state.errorMessage}>
            <label className="text-danger">{this.state.errorMessage}</label>
          </div>
          <div className="row mt-2 input-group">
            <textarea
              className="form-control text-monospace"
              rows="10"
              readOnly
              value={this.state.responseAPDULog}
              ref={el => (this.outputResponseAPDULog = el)}
            />
            <div className="w-100" />
            <button
              className="btn btn-primary w-100"
              onClick={this.onClickClear.bind(this)}
            >
              Clear
            </button>
          </div>
        </div>
      </div>
    );
  }
}

export default MainPage;
