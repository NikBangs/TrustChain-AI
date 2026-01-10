// Solidity Smart Contract

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TrustChain {
    mapping(string => bool) public fraudReports;

    function reportSite(string memory domain) public {
        fraudReports[domain] = true;
    }

    function isReported(string memory domain) public view returns (bool) {
        return fraudReports[domain];
    }
}
