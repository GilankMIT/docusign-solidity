// SPDX-License-Identifier: GPL-3.0

pragma solidity ^0.8.0;

contract Docusigner {
    
    struct DocumentObject {
        string checksum;
        string nameOfFile;
        address owner;
        bytes32 documentId;
    }

    mapping(bytes32 => DocumentObject) private documents;
    mapping(bytes32 => mapping(address => bytes)) private signatures;
    
    event DocumentStored(bytes32 indexed documentId);
    
    function storeDocument(string memory _checksum, string memory _nameOfFile) public returns (string memory) {
        bytes32 documentId = keccak256(abi.encodePacked(msg.sender, block.timestamp));
        DocumentObject storage newDocument = documents[documentId];
        newDocument.checksum = _checksum;
        newDocument.nameOfFile = _nameOfFile;
        newDocument.owner = msg.sender;
        newDocument.documentId = documentId;
        emit DocumentStored(documentId);
        return "";
    }
    
    function signDocument(bytes32 _documentId, bytes memory _signature) public {
        signatures[_documentId][msg.sender] = _signature;
    }

    function verifyDoc(bytes32 _documentId, address _publicKey) public view returns (bool) {
        DocumentObject storage document = documents[_documentId];
        require(document.owner != address(0), "Document does not exist");
        bytes memory signature = getSignature(_documentId, _publicKey);

        bytes32 messageHash = keccak256(abi.encodePacked(document.checksum));
        bytes32 ethSignedMessageHash = toEthSignedMessageHash(messageHash);

        return recoverSigner(ethSignedMessageHash, signature) == _publicKey;
    }
    
    function getDocument(bytes32 _documentId) internal view returns (DocumentObject memory) {
        return documents[_documentId];
    }
    
    function getSignature(bytes32 _documentId, address _address) internal view returns (bytes memory) {
        return signatures[_documentId][_address];
    }
    
    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }

    function recoverSigner(bytes32 _ethSignedMessageHash, bytes memory _signature) internal pure returns (address) {
        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(_signature, 32))
            s := mload(add(_signature, 64))
            v := byte(0, mload(add(_signature, 96)))
        }

        if (v < 27) {
            v += 27;
        }

        return ecrecover(_ethSignedMessageHash, v, r, s);
    }
}
