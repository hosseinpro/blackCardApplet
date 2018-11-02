import React, { Component } from "react";
import "./App.css";
import MainPage from "./components/MainPage";

class App extends Component {
  render() {
    return (
      <div className="App">
        <div className="container">
          <h3 className="mt-4">BlackCard Tester</h3>
          <MainPage smartcardBridgeAddress="http://localhost:3333" />
          {/* <MainPage smartcardBridgeAddress="http://192.168.56.2:3333" /> */}
        </div>
      </div>
    );
  }
}

export default App;
