// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title SecurityRegistry
 * @notice On-chain registry for Audity security findings on Somnia Testnet (chain 50312).
 * @dev Stores vulnerability findings submitted by scanner agents and confirmed/rejected
 *      by validator agents. Events are picked up by Somnia Reactivity subscribers.
 *
 *      Gas note (Somnia): cold SLOAD ~476x Ethereum cost, LOG ~13x cost.
 *      All handlers are kept minimal — state cached in memory before storage writes.
 *
 * Finding lifecycle:
 *   submitFinding()  → FindingSubmitted  (scanner agent submits)
 *   confirmFinding() → FindingConfirmed  (validator confirms, +50 bp rep on scanner)
 *   rejectFinding()  → FindingRejected   (validator rejects, -100 bp rep on scanner)
 */
contract SecurityRegistry {

    // ─── Reentrancy Guard ────────────────────────────────────────────────────

    uint256 private _status;
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;

    modifier nonReentrant() {
        require(_status != _ENTERED, "Reentrant call");
        _status = _ENTERED;
        _;
        _status = _NOT_ENTERED;
    }

    // ─── Constants ───────────────────────────────────────────────────────────

    /// @notice Reputation bonus in basis points awarded on finding confirmation.
    uint256 public constant REP_SUCCESS_BONUS   = 50;
    /// @notice Reputation penalty in basis points applied on finding rejection.
    uint256 public constant REP_FAILURE_PENALTY = 100;
    /// @notice Maximum reputation ceiling in basis points (10000 = 100%).
    uint256 public constant MAX_REPUTATION      = 10_000;

    // ─── Enums ───────────────────────────────────────────────────────────────

    /// @notice Lifecycle status of a vulnerability finding.
    enum FindingStatus { Pending, Confirmed, Rejected }

    // ─── Structs ────────────────────────────────────────────────────────────

    /**
     * @notice A vulnerability finding submitted by a scanner agent.
     * @param contractAddress The audited contract's address (address(0) if source-only).
     * @param vulnType Vulnerability class: reentrancy|overflow|access-control|logic|flash-loan.
     * @param severity Severity level: critical|high|medium|low.
     * @param description Human-readable description of the vulnerability.
     * @param scannerAgent Identifier of the scanner agent that submitted this finding.
     * @param scanner On-chain address of the scanner agent wallet.
     * @param validator On-chain address of the validator (address(0) until reviewed).
     * @param status Current lifecycle status.
     * @param rewardSTT Reward amount in STT wei for confirmed findings.
     * @param submittedAt Block timestamp when the finding was submitted.
     * @param reviewedAt Block timestamp when the finding was reviewed (0 if pending).
     */
    struct Finding {
        address contractAddress;
        string  vulnType;
        string  severity;
        string  description;
        string  scannerAgent;
        address scanner;
        address validator;
        FindingStatus status;
        uint256 rewardSTT;
        uint256 submittedAt;
        uint256 reviewedAt;
    }

    // ─── State ───────────────────────────────────────────────────────────────

    /// @notice All findings indexed by their unique ID.
    mapping(bytes32 => Finding) public findings;

    /// @notice Ordered list of all finding IDs.
    bytes32[] public findingIds;

    /// @notice Scanner reputation scores in basis points (0–10000) per address.
    mapping(address => uint256) public scannerReputation;

    // ─── Events ──────────────────────────────────────────────────────────────

    /**
     * @notice Emitted when a scanner agent submits a new vulnerability finding.
     * @param findingId Unique finding identifier.
     * @param contractAddress Audited contract address (address(0) for source-only scans).
     * @param vulnType Vulnerability class identifier.
     * @param severity Severity level: critical|high|medium|low.
     * @param description Human-readable vulnerability description.
     * @param scannerAgent Scanner agent identifier string.
     */
    event FindingSubmitted(
        bytes32 indexed findingId,
        address indexed contractAddress,
        string vulnType,
        string severity,
        string description,
        string scannerAgent
    );

    /**
     * @notice Emitted when a validator confirms a finding as valid.
     * @param findingId The confirmed finding's unique identifier.
     * @param validator Address of the confirming validator.
     * @param scanner Address of the scanner whose reputation was increased.
     */
    event FindingConfirmed(
        bytes32 indexed findingId,
        address indexed validator,
        address indexed scanner
    );

    /**
     * @notice Emitted when a validator rejects a finding as invalid.
     * @param findingId The rejected finding's unique identifier.
     * @param validator Address of the rejecting validator.
     * @param scanner Address of the scanner whose reputation was penalised.
     */
    event FindingRejected(
        bytes32 indexed findingId,
        address indexed validator,
        address indexed scanner
    );

    // ─── Custom Errors ───────────────────────────────────────────────────────

    /// @dev Reverts with `FindingNotFound` when the finding ID does not exist.
    error FindingNotFound(bytes32 findingId);
    /// @dev Reverts with `FindingNotPending` when the finding has already been reviewed.
    error FindingNotPending(bytes32 findingId);
    /// @dev Reverts with `EmptyVulnType` when an empty vulnerability type is provided.
    error EmptyVulnType();
    /// @dev Reverts with `EmptySeverity` when an empty severity string is provided.
    error EmptySeverity();

    // ─── Constructor ─────────────────────────────────────────────────────────

    constructor() {
        _status = _NOT_ENTERED;
    }

    // ─── Core Functions ──────────────────────────────────────────────────────

    /**
     * @notice Submit a new vulnerability finding from a scanner agent.
     * @dev The caller (msg.sender) is recorded as the scanner's on-chain address.
     *      Initialises scanner reputation to 5000 bp (50%) on first submission.
     *      Emits `FindingSubmitted` — Somnia Reactivity validators pick this up.
     * @param contractAddress Address of the audited contract (address(0) for source-only).
     * @param vulnType Vulnerability class: reentrancy|overflow|access-control|logic|flash-loan.
     * @param severity Severity level: critical|high|medium|low.
     * @param description Human-readable description of the vulnerability.
     * @param scannerAgent Identifier of the scanner agent (off-chain label).
     * @param rewardSTT Reward amount in STT wei for a confirmed finding (can be 0).
     * @return findingId Unique identifier for the submitted finding.
     * @dev Reverts with `EmptyVulnType` if vulnType is empty.
     * @dev Reverts with `EmptySeverity` if severity is empty.
     */
    function submitFinding(
        address contractAddress,
        string calldata vulnType,
        string calldata severity,
        string calldata description,
        string calldata scannerAgent,
        uint256 rewardSTT
    ) external returns (bytes32 findingId) {
        if (bytes(vulnType).length == 0) revert EmptyVulnType();
        if (bytes(severity).length == 0) revert EmptySeverity();

        findingId = keccak256(abi.encodePacked(
            msg.sender,
            contractAddress,
            vulnType,
            severity,
            block.timestamp,
            findingIds.length
        ));

        // Cache in memory before storage write (Somnia: minimise cold SLOADs)
        Finding memory f = Finding({
            contractAddress: contractAddress,
            vulnType:        vulnType,
            severity:        severity,
            description:     description,
            scannerAgent:    scannerAgent,
            scanner:         msg.sender,
            validator:       address(0),
            status:          FindingStatus.Pending,
            rewardSTT:       rewardSTT,
            submittedAt:     block.timestamp,
            reviewedAt:      0
        });

        findings[findingId] = f;
        findingIds.push(findingId);

        // Initialise scanner reputation if first submission
        if (scannerReputation[msg.sender] == 0) {
            scannerReputation[msg.sender] = 5_000;
        }

        emit FindingSubmitted(findingId, contractAddress, vulnType, severity, description, scannerAgent);
    }

    /**
     * @notice Confirm a pending finding as a valid vulnerability.
     * @dev Rewards the scanner with +50 bp reputation (capped at MAX_REPUTATION).
     *      Emits `FindingConfirmed` — Somnia Reactivity validators pick this up.
     * @param findingId The ID of the finding to confirm.
     * @dev Reverts with `FindingNotFound` if findingId does not exist.
     * @dev Reverts with `FindingNotPending` if finding has already been reviewed.
     */
    function confirmFinding(bytes32 findingId) external {
        Finding storage f = findings[findingId];
        if (f.scanner == address(0)) revert FindingNotFound(findingId);
        if (f.status != FindingStatus.Pending) revert FindingNotPending(findingId);

        // Cache scanner address before storage writes
        address scanner = f.scanner;

        f.status    = FindingStatus.Confirmed;
        f.validator = msg.sender;
        f.reviewedAt = block.timestamp;

        // Reputation adjustment — capped at MAX_REPUTATION
        uint256 currentRep = scannerReputation[scanner];
        scannerReputation[scanner] = currentRep + REP_SUCCESS_BONUS > MAX_REPUTATION
            ? MAX_REPUTATION
            : currentRep + REP_SUCCESS_BONUS;

        emit FindingConfirmed(findingId, msg.sender, scanner);
    }

    /**
     * @notice Reject a pending finding as invalid.
     * @dev Penalises the scanner with -100 bp reputation (floored at 0).
     *      Emits `FindingRejected` — Somnia Reactivity validators pick this up.
     * @param findingId The ID of the finding to reject.
     * @dev Reverts with `FindingNotFound` if findingId does not exist.
     * @dev Reverts with `FindingNotPending` if finding has already been reviewed.
     */
    function rejectFinding(bytes32 findingId) external {
        Finding storage f = findings[findingId];
        if (f.scanner == address(0)) revert FindingNotFound(findingId);
        if (f.status != FindingStatus.Pending) revert FindingNotPending(findingId);

        address scanner = f.scanner;

        f.status    = FindingStatus.Rejected;
        f.validator = msg.sender;
        f.reviewedAt = block.timestamp;

        // Reputation adjustment — floored at 0
        uint256 currentRep = scannerReputation[scanner];
        scannerReputation[scanner] = currentRep >= REP_FAILURE_PENALTY
            ? currentRep - REP_FAILURE_PENALTY
            : 0;

        emit FindingRejected(findingId, msg.sender, scanner);
    }

    // ─── Views ───────────────────────────────────────────────────────────────

    /**
     * @notice Returns all finding IDs in submission order.
     * @return Array of all finding IDs.
     */
    function getFindingIds() external view returns (bytes32[] memory) {
        return findingIds;
    }

    /**
     * @notice Returns a finding by its ID.
     * @param findingId The finding to retrieve.
     * @return The Finding struct.
     */
    function getFinding(bytes32 findingId) external view returns (Finding memory) {
        return findings[findingId];
    }

    /**
     * @notice Returns total number of findings submitted.
     * @return Count of all submitted findings.
     */
    function totalFindings() external view returns (uint256) {
        return findingIds.length;
    }

    /**
     * @notice Returns the reputation of a scanner address as a 0–100 percentage.
     * @param scanner Address of the scanner agent wallet.
     * @return Reputation as integer percentage (0–100).
     */
    function getReputationPercent(address scanner) external view returns (uint256) {
        return scannerReputation[scanner] / 100;
    }
}
