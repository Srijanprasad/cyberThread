// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/// @title ModelRegistry
/// @notice Detector artifacts are usable only after `threshold` distinct approvers sign off.
contract ModelRegistry is AccessControl {
    bytes32 public constant PUBLISHER_ROLE = keccak256("PUBLISHER_ROLE");
    bytes32 public constant APPROVER_ROLE = keccak256("APPROVER_ROLE");
    uint8 public immutable threshold;

    struct Model {
        bytes32 datasetHash;
        string detector;
        string version;
        address publisher;
        uint8 approvals;
        bool revoked;
        uint64 ts;
    }

    mapping(bytes32 => Model) public models;
    mapping(bytes32 => mapping(address => bool)) public approvedBy;

    event ModelRegistered(bytes32 indexed modelHash, string detector, string version, bytes32 datasetHash, address publisher);
    event ModelApproved(bytes32 indexed modelHash, address approver, uint8 approvals);
    event ModelRevoked(bytes32 indexed modelHash, address by);

    constructor(address admin, uint8 _threshold) {
        require(_threshold > 0, "threshold");
        threshold = _threshold;
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    function register(
        bytes32 modelHash,
        bytes32 datasetHash,
        string calldata detector,
        string calldata version
    ) external onlyRole(PUBLISHER_ROLE) {
        require(models[modelHash].ts == 0, "exists");
        models[modelHash] = Model(datasetHash, detector, version, msg.sender, 0, false, uint64(block.timestamp));
        emit ModelRegistered(modelHash, detector, version, datasetHash, msg.sender);
    }

    function approve(bytes32 modelHash) external onlyRole(APPROVER_ROLE) {
        Model storage m = models[modelHash];
        require(m.ts != 0 && !m.revoked, "unknown or revoked");
        require(!approvedBy[modelHash][msg.sender], "already approved");
        approvedBy[modelHash][msg.sender] = true;
        m.approvals += 1;
        emit ModelApproved(modelHash, msg.sender, m.approvals);
    }

    function revoke(bytes32 modelHash) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(models[modelHash].ts != 0, "unknown");
        models[modelHash].revoked = true;
        emit ModelRevoked(modelHash, msg.sender);
    }

    function isApproved(bytes32 h) external view returns (bool) {
        Model storage m = models[h];
        return m.ts != 0 && !m.revoked && m.approvals >= threshold;
    }
}
