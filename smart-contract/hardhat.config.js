require("@nomicfoundation/hardhat-toolbox");

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.20", // Compatible with ^0.8.0 pragma
  },
  networks: {
    localhost: {
      url: "http://127.0.0.1:8545" // Local Hardhat node
    }
  }
};
