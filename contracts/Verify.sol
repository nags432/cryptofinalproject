// SPDX-License-Identifier: MIT
pragma solidity ^0.8.2;

import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "hardhat/console.sol";

contract AttestorRegistry {
    // Define a struct to hold the public key and weight
    struct Attestor {
        address pk;
        uint weight;
    }

    // Define a struct for the Interval
    struct Leaf {
        string signature;
        uint256 L;
        uint256 R;
        string _r;
        string _s;
        uint8 _v;
    }

    struct T_entry {
        Leaf sigTuple;
        bytes32[] sigsProof;
        bytes attestorAddress;
        bytes32[] attestorProof;
        bytes32 msgHash;
    }

    // Declare a map make sure no duplicates exist
    mapping(address => bool) public globalAttestorsMap;

    // Declare a dynamic array to hold the list of attestors
    Attestor[] public globalAttestorsList;

    // Declare Attestors Merkle Root
    //bytes32 attestorRoot;

    using MerkleProof for bytes32[];
    using Math for uint256;
    using Strings for address;

    // Event to log the addition of a new attestor
    event AttestorAdded(address indexed attestor, uint weight);

    // Function to add a new attestor to the global list
    function addAttestor(address _attestor) public {
        require(_attestor != address(0), "Invalid address");
        require(!globalAttestorsMap[_attestor], "Attestor already exists");

        // Add new pk to map
        globalAttestorsMap[_attestor] = true;
        
        // Create a new Attestor struct with weight initialized to 100
        Attestor memory newAttestor = Attestor({
            pk: _attestor,
            weight: 100
        });

        // Add the new attestor to the global list
        globalAttestorsList.push(newAttestor);

        // Emit an event for the addition of the new attestor
        emit AttestorAdded(_attestor, 1);
    }

    // Function to get an attestor by index
    function getAttestor(uint index) public view returns (address, uint) {
        require(index < globalAttestorsList.length, "Index out of bounds");
        Attestor storage attestor = globalAttestorsList[index];
        return (attestor.pk, attestor.weight);
    }

    //function storeRoot(bytes32 memory root) public {
    //    attestorRoot = root;
    //}

    

    function intToInd(Leaf[] memory arr, uint256 coin, uint256 start, uint256 end) public pure returns (uint256) {
        // Base Condition
        if (start > end) return 0;

        // Find the middle index
        uint256 mid = (start + end) / 2;

        // Compare mid with given key coin
        if (arr[mid].L <= coin && coin <= arr[mid].R) return uint256(mid);

        // If element at mid is greater than coin,
        // search in the left half of mid
        if (arr[mid].L > coin)
            return intToInd(arr, coin, start, mid - 1);
        else
            // If element at mid is smaller than coin,
            // search in the right half of mid
            return intToInd(arr, coin, mid + 1, end);
    }

    function stringToBytes32(string memory source) public pure returns (bytes32 result) {
        bytes memory tempEmptyStringTest = bytes(source);
        if (tempEmptyStringTest.length == 0) {
            return 0x0;
        }

        assembly {
            result := mload(add(source, 32))
        }
    }


    // remember the types of the public key you used (string)

    function verifyCertificate(T_entry[] memory T, string memory sigsRoot, uint256 signedWeight, uint256 provenWeight) public view returns (bool) {
        
        require(signedWeight > provenWeight, "signedWeight not greater than provenWeight");
        //uint256 numReveals = (k + q) / Math.log2(signedWeight / provenWeight);

        for (uint256 i = 0; i < T.length; i++) {
            //MerkleProof.verify(proof, root, leaf);
            require(MerkleProof.verify(T[i].sigsProof, stringToBytes32(sigsRoot), keccak256(bytes.concat(keccak256(abi.encode(T[i].sigTuple.signature))))), "Signature proof failed");
        }

        return true;
    }

}
