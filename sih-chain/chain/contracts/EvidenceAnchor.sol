// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

/// @title EvidenceAnchor
/// @notice Append-only registry of Merkle roots over alert/evidence log entries.
///         Per-sensor sequence numbers make skipped or deleted batches detectable.
contract EvidenceAnchor is AccessControl {
    bytes32 public constant SENSOR_ROLE = keccak256("SENSOR_ROLE");

    struct Batch {
        bytes32 root;
        bytes32 prevRoot; // previous root from the same sensor (0x0 for the first)
        address sensor;
        uint64 firstSeq;
        uint64 lastSeq;
        uint64 ts;
        string uri;
    }

    Batch[] public batches;
    mapping(address => uint64) public nextSeq;
    mapping(address => bytes32) public lastRoot;

    event BatchAnchored(
        uint256 indexed id,
        address indexed sensor,
        bytes32 root,
        bytes32 prevRoot,
        uint64 firstSeq,
        uint64 lastSeq,
        string uri
    );

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    function anchorBatch(
        bytes32 root,
        uint64 firstSeq,
        uint64 lastSeq,
        string calldata uri
    ) external onlyRole(SENSOR_ROLE) returns (uint256 id) {
        require(lastSeq >= firstSeq, "bad range");
        require(firstSeq == nextSeq[msg.sender], "sequence gap");
        id = batches.length;
        bytes32 prev = lastRoot[msg.sender];
        batches.push(Batch(root, prev, msg.sender, firstSeq, lastSeq, uint64(block.timestamp), uri));
        nextSeq[msg.sender] = lastSeq + 1;
        lastRoot[msg.sender] = root;
        emit BatchAnchored(id, msg.sender, root, prev, firstSeq, lastSeq, uri);
    }

    function verify(uint256 id, bytes32 leaf, bytes32[] calldata proof) external view returns (bool) {
        return MerkleProof.verifyCalldata(proof, batches[id].root, leaf);
    }

    function batchCount() external view returns (uint256) {
        return batches.length;
    }
}
