// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract HashStorage {
    string public storedHash;

    function storeHash(string memory _hash) public {
        storedHash = _hash;
    }

    function getHash() public view returns (string memory) {
        return storedHash;
    }
}
