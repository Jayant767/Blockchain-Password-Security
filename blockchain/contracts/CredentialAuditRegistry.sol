// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Anchors opaque credential lifecycle commitments. This contract does not authenticate passwords.
contract CredentialAuditRegistry {
    error Unauthorized();
    error ZeroAddress();
    error InvalidCredentialId();
    error InvalidCommitment();
    error AlreadyRegistered();
    error NotRegistered();
    error InvalidVersion(uint64 expected, uint64 supplied);
    error AlreadyRevoked();

    address public owner;
    mapping(address => bool) public writers;

    struct Credential {
        uint64 version;
        bytes32 commitment;
        bool revoked;
        uint64 updatedAt;
    }
    mapping(bytes32 => Credential) private credentials;

    event WriterUpdated(address indexed writer, bool enabled);
    event CredentialRegistered(bytes32 indexed credentialId, uint64 version, bytes32 commitment);
    event CredentialUpdated(bytes32 indexed credentialId, uint64 version, bytes32 commitment);
    event CredentialRevoked(bytes32 indexed credentialId, uint64 version);

    modifier onlyOwner() { if (msg.sender != owner) revert Unauthorized(); _; }
    modifier onlyWriter() { if (!writers[msg.sender]) revert Unauthorized(); _; }

    constructor() {
        owner = msg.sender;
        writers[msg.sender] = true;
        emit WriterUpdated(msg.sender, true);
    }

    function setWriter(address writer, bool enabled) external onlyOwner {
        if (writer == address(0)) revert ZeroAddress();
        writers[writer] = enabled;
        emit WriterUpdated(writer, enabled);
    }

    function registerCredential(bytes32 credentialId, uint64 version, bytes32 commitment) external onlyWriter {
        if (credentialId == bytes32(0)) revert InvalidCredentialId();
        if (commitment == bytes32(0)) revert InvalidCommitment();
        if (credentials[credentialId].version != 0) revert AlreadyRegistered();
        if (version != 1) revert InvalidVersion(1, version);
        credentials[credentialId] = Credential(version, commitment, false, uint64(block.timestamp));
        emit CredentialRegistered(credentialId, version, commitment);
    }

    function updateCredential(bytes32 credentialId, uint64 version, bytes32 commitment) external onlyWriter {
        Credential storage current = credentials[credentialId];
        if (current.version == 0) revert NotRegistered();
        if (current.revoked) revert AlreadyRevoked();
        uint64 expected = current.version + 1;
        if (version != expected) revert InvalidVersion(expected, version);
        if (commitment == bytes32(0)) revert InvalidCommitment();
        current.version = version;
        current.commitment = commitment;
        current.updatedAt = uint64(block.timestamp);
        emit CredentialUpdated(credentialId, version, commitment);
    }

    function revokeCredential(bytes32 credentialId) external onlyWriter {
        Credential storage current = credentials[credentialId];
        if (current.version == 0) revert NotRegistered();
        if (current.revoked) revert AlreadyRevoked();
        current.revoked = true;
        current.updatedAt = uint64(block.timestamp);
        emit CredentialRevoked(credentialId, current.version);
    }

    function getCredential(bytes32 credentialId) external view returns (uint64 version, bytes32 commitment, bool revoked, uint64 updatedAt) {
        Credential storage c = credentials[credentialId];
        return (c.version, c.commitment, c.revoked, c.updatedAt);
    }
}
