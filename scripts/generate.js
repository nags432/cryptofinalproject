const EthCrypto = require("eth-crypto");
const oz=  require("@openzeppelin/merkle-tree");
const StandardMerkleTree = oz.StandardMerkleTree;
const hre = require("hardhat");
const { ethers } = require("ethers");
const fs = require("fs");

async function setup() {

    // Connect to the right network
    const network = await hre.ethers.provider.getNetwork();
    console.log(`Connected to network: ${network.name} (chainId: ${network.chainId})`);

    const localUser = EthCrypto.createIdentity();

    const msg = localUser.publicKey;
    const msgHash = EthCrypto.hash.keccak256(msg);
    const globalAttestorsList = [];

    const privateStore = [];

    let contractAddress = '0x5FbDB2315678afecb367f032d93F642f64180aa3';
    const AttestorRegistry = await hre.ethers.getContractFactory("AttestorRegistry");
    const attestorRegistry = await AttestorRegistry.attach(contractAddress);

    console.log("AttestorRegistry attached to:", attestorRegistry.address);


    var i = 6000;
    console.log('create synthetic users and signatures');
    while (i > 0) {
        const signerIdentity = EthCrypto.createIdentity();

        const attestorAddress = EthCrypto.publicKey.toAddress(signerIdentity.publicKey);
        // choose a few pks from the list to create signatures from
        
        if (i % 3 == 0 || i % 7 == 0) {
            const signature = EthCrypto.sign(signerIdentity.privateKey, msgHash);

            // populate the local store with signatures

            privateStore.push(({'pk': attestorAddress, 'sig':signature}));

        }
        globalAttestorsList.push(({'pk': attestorAddress, 'weight':100}));

        // populate the globalAttestorsList on smart contract with public key
        // This is specific to this project setup.  Obviously each user would only populate
        // themselves in a real-world scenario.

        const tx = await attestorRegistry.addAttestor(attestorAddress);
        // Wait for the transaction to be mined
        await tx.wait();

        i = i -1;
    }


    // create the certificate with both privateStore and globalAttestorsList in hand

    const signersList = {};
    const sigs = [];
    var signedWeight = 0;
    const provenWeight = 200;



    function verifySignature(attestorPKProve, msg, signature) {
        const signer = EthCrypto.publicKey.toAddress(EthCrypto.recoverPublicKey(signature, EthCrypto.hash.keccak256(msg)));
        return (attestorPKProve == signer);
    }


    function populateSignersList(sigData, provenWeight){
        
        const sigPK = sigData.pk;
        const signature = sigData.sig;

        var i = 0;
        
            for (const obj of globalAttestorsList) {
                
                // if pk of signature matches pk in globalAttestorsList and i is not already in signersList, then added to SignersList

                if (obj.pk == sigPK && !Object.keys(signersList).includes(i) && verifySignature(obj.pk, msg ,signature)) {
                    signersList[i] = signature;
                    const weight = obj.weight;
                    signedWeight = signedWeight + weight;
                    
                }
                
                i = i + 1;
            }
    }

    console.log('populated signers list, verify each signature');
    privateStore.forEach(populateSignersList);

    
    var iter = 0;

    while (iter < globalAttestorsList.length) {
        var L;
        var R;

        if (iter == 0) {
            L = 0;
        } else {
            L = sigs[iter - 1].R
        }

        result = {'sig': '0x'+'00'.repeat(65), 'L': L, 'R': L};

        for (const [key, value] of Object.entries(signersList)) {
            if (iter == key) {
                result.sig = signersList[iter];
                result.R = L + globalAttestorsList[iter].weight;
            } 
        }
        sigs.push(result);
        iter = iter + 1;

    }

    
    // merkle tree for signatures
    function buildMerkleTree(leaves) {
        const merkleLeaves = [];
        const values = ['string'];
        for (sigData of leaves) {
            merkleLeaves.push([sigData.sig]);
        }

        
        const tree = StandardMerkleTree.of(merkleLeaves, values, sortLeaves = false);

        return tree;

    }

    const sigTree = buildMerkleTree(sigs);

    // merkle tree for attestors
    const values = ["string", "uint256"];
    const merkleLeaves = [];
    for (data of globalAttestorsList) {
        merkleLeaves.push([data.pk, data.weight])
    }
    
    const attestorsTree = StandardMerkleTree.of(merkleLeaves, values, sortLeaves = false);




    let IntToInd = function (arr, coin, start, end) {
    
        // Base Condition
        if (start > end) return false;
    
        // Find the middle index
        let mid = Math.floor((start + end) / 2);

    
        // Compare mid with given key x
        if (parseFloat(arr[mid].L) <= coin && coin <= parseFloat(arr[mid].R)) return mid;
    
        // If element at mid is greater than x,
        // search in the left half of mid
        if (parseFloat(arr[mid].L) > coin)
            return IntToInd(arr, coin, start, mid - 1);
        else
    
            // If element at mid is smaller than x,
            // search in the right half of mid
            return IntToInd(arr, coin, mid + 1, end);
    }

    function createMap(k, q, signedWeight, provenWeight, msg, leaves, sigTree, attestorsTree, msgHash) {
        const sigsRoot = sigTree.root;
        const attRoot = attestorsTree.root;

        const numReveals = (k + q) / (Math.log2(signedWeight/provenWeight));
        var j = 0;

        const T = new Map();

        while (j < numReveals) {
            const HinJ = j+sigsRoot+provenWeight+msg+attRoot;
            const coinJ = parseInt(EthCrypto.hash.keccak256(HinJ)) % 10000000 / 10000000;
            const ind = IntToInd(leaves, coinJ * signedWeight,0, leaves.length);
            const _r = leaves[ind].sig.slice(0, 66);
            const _s = "0x" + leaves[ind].sig.slice(66, 130);
            const _v = parseInt(leaves[ind].sig.slice(130, 132), 16);
            if (!T.has(ind)) {
                const sigTuple = {'signature': leaves[ind].sig,'L': leaves[ind].L, 'R': leaves[ind], '_r': _r, '_s': _s, '_v': _v };
                T[ind] = {'sigTuple': sigTuple, 'sigsProof': sigTree.getProof(ind), 'attestorAddress': globalAttestorsList[ind].pk, 'attestorProof': attestorsTree.getProof(ind), 'msgHash': msgHash}
                
            }
            j = j+1;

        }

        return T
    }

    const k = 20;
    const q = 20;

    T = createMap(k,q,signedWeight, provenWeight, msg, sigs, sigTree, attestorsTree, msgHash);

    

    T_array = [];

    for (const [key, value] of Object.entries(T)) {
        T_array.push(value);
    };

    fs.writeFileSync("./data/certificate.json", JSON.stringify([T_array, sigTree.root, signedWeight, provenWeight]));
    fs.writeFileSync("./data/allSignatures.json", JSON.stringify(privateStore));

    // call to the smart contract here:
    //const tx = await attestorRegistry.verifyCertificate(T_array, sigTree.root, signedWeight, provenWeight);
}

// Execute the main function
setup();
