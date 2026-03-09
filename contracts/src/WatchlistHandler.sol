// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title WatchlistHandler
 * @notice Somnia Reactivity handler for Audity's contract watchlist.
 * @dev Receives BlockTick (periodic) or Schedule (one-off) events from the
 *      Somnia Reactivity Precompile and emits RescanRequested for each watched
 *      contract. The Audity backend subscribes to RescanRequested and triggers
 *      the LLM scanner automatically.
 *
 *      Deployment flow:
 *        1. Deploy this contract → note address as WATCHLIST_HANDLER_ADDRESS
 *        2. Backend calls createOnchainBlockTickSubscription({ handlerContractAddress })
 *           or scheduleOnchainCronJob({ handlerContractAddress }) via Reactivity SDK
 *        3. On each tick, _onEvent fires → RescanRequested emitted per watched contract
 *        4. Backend Reactivity subscription receives RescanRequested → runs LLM scan
 *
 *      Somnia gas note: LOG opcodes are ~13x Ethereum cost. Keep watchedContracts
 *      small (recommended ≤ 20 addresses) to bound gas per tick invocation.
 *
 *      Inline SomniaEventHandler base — avoids npm package dependency in Foundry.
 */

// ─── Inline SomniaEventHandler base ──────────────────────────────────────────

/**
 * @notice Base contract for Somnia Reactivity handlers.
 * @dev Restricts `onEvent` to the Somnia Reactivity Precompile at 0x0100.
 *      Inheriting contracts must override `_onEvent`.
 */
abstract contract SomniaEventHandler {
    /// @dev Somnia Reactivity Precompile address — the only valid caller of onEvent.
    address private constant REACTIVITY_PRECOMPILE =
        0x0000000000000000000000000000000000000100;

    /// @dev Reverts with `OnlyPrecompile` when caller is not the Reactivity Precompile.
    error OnlyPrecompile(address caller);

    /**
     * @notice Entry point called by the Reactivity Precompile on each subscribed event.
     * @param emitter The contract that emitted the original event (or precompile for system events).
     * @param eventTopics Topics from the original event.
     * @param data ABI-encoded event data.
     * @dev Reverts with `OnlyPrecompile` if msg.sender is not the Reactivity Precompile.
     */
    function onEvent(
        address emitter,
        bytes32[] calldata eventTopics,
        bytes calldata data
    ) external {
        if (msg.sender != REACTIVITY_PRECOMPILE) revert OnlyPrecompile(msg.sender);
        _onEvent(emitter, eventTopics, data);
    }

    /**
     * @notice Override in handler contracts to implement event reaction logic.
     * @param emitter The contract that emitted the triggering event.
     * @param eventTopics Topics from the triggering event.
     * @param data ABI-encoded event data from the triggering event.
     */
    function _onEvent(
        address emitter,
        bytes32[] calldata eventTopics,
        bytes calldata data
    ) internal virtual;
}

// ─── WatchlistHandler ─────────────────────────────────────────────────────────

contract WatchlistHandler is SomniaEventHandler {

    // ─── Events ──────────────────────────────────────────────────────────────

    /**
     * @notice Emitted on each tick for every contract in the watchlist.
     * @dev Audity backend subscribes to this event via Somnia Reactivity WebSocket.
     *      One event per watched contract per tick — keep watchlist small.
     * @param contractAddress The watched contract that should be re-scanned.
     * @param blockNumber The block at which the tick was processed.
     */
    event RescanRequested(address indexed contractAddress, uint256 blockNumber);

    /**
     * @notice Emitted when a contract is added to the watchlist.
     * @param contractAddress The newly watched contract address.
     * @param addedBy The address that called addContract.
     */
    event ContractAdded(address indexed contractAddress, address indexed addedBy);

    /**
     * @notice Emitted when a contract is removed from the watchlist.
     * @param contractAddress The contract address removed from the watchlist.
     */
    event ContractRemoved(address indexed contractAddress);

    // ─── Custom Errors ────────────────────────────────────────────────────────

    /// @dev Reverts with `OnlyOwner` when caller is not the contract owner.
    error OnlyOwner(address caller);
    /// @dev Reverts with `AlreadyWatched` when the contract is already in the watchlist.
    error AlreadyWatched(address contractAddress);
    /// @dev Reverts with `NotWatched` when the contract is not in the watchlist.
    error NotWatched(address contractAddress);
    /// @dev Reverts with `WatchlistFull` when the watchlist has reached MAX_WATCHED.
    error WatchlistFull();
    /// @dev Reverts with `ZeroAddress` when address(0) is provided.
    error ZeroAddress();

    // ─── State ───────────────────────────────────────────────────────────────

    /// @notice Maximum watchlist size to bound gas per tick (Somnia LOG ~13x cost).
    uint256 public constant MAX_WATCHED = 20;

    /// @notice The owner of this handler — can add/remove contracts.
    address public immutable owner;

    /// @notice Ordered list of watched contract addresses.
    address[] public watchedContracts;

    /// @notice Fast membership check for watched contracts.
    mapping(address => bool) public isWatched;

    // ─── Constructor ─────────────────────────────────────────────────────────

    constructor() {
        owner = msg.sender;
    }

    // ─── Modifiers ───────────────────────────────────────────────────────────

    modifier onlyOwner() {
        if (msg.sender != owner) revert OnlyOwner(msg.sender);
        _;
    }

    // ─── Watchlist Management ─────────────────────────────────────────────────

    /**
     * @notice Add a contract address to the periodic rescan watchlist.
     * @param contractAddress The deployed contract to watch for vulnerabilities.
     * @dev Reverts with `ZeroAddress` if contractAddress is address(0).
     * @dev Reverts with `WatchlistFull` if the watchlist has reached MAX_WATCHED.
     * @dev Reverts with `AlreadyWatched` if the contract is already watched.
     * @dev Reverts with `OnlyOwner` if caller is not the owner.
     */
    function addContract(address contractAddress) external onlyOwner {
        if (contractAddress == address(0)) revert ZeroAddress();
        if (watchedContracts.length >= MAX_WATCHED) revert WatchlistFull();
        if (isWatched[contractAddress]) revert AlreadyWatched(contractAddress);

        isWatched[contractAddress] = true;
        watchedContracts.push(contractAddress);

        emit ContractAdded(contractAddress, msg.sender);
    }

    /**
     * @notice Remove a contract address from the watchlist.
     * @param contractAddress The contract to stop watching.
     * @dev Uses swap-and-pop for O(n) removal without leaving gaps.
     * @dev Reverts with `NotWatched` if the contract is not in the watchlist.
     * @dev Reverts with `OnlyOwner` if caller is not the owner.
     */
    function removeContract(address contractAddress) external onlyOwner {
        if (!isWatched[contractAddress]) revert NotWatched(contractAddress);

        isWatched[contractAddress] = false;

        uint256 len = watchedContracts.length;
        for (uint256 i = 0; i < len; i++) {
            if (watchedContracts[i] == contractAddress) {
                // Swap with last element and pop
                watchedContracts[i] = watchedContracts[len - 1];
                watchedContracts.pop();
                break;
            }
        }

        emit ContractRemoved(contractAddress);
    }

    // ─── Reactivity Handler ───────────────────────────────────────────────────

    /**
     * @notice Called by the Reactivity Precompile on each BlockTick or Schedule event.
     * @dev Emits RescanRequested for every contract in the watchlist.
     *      WARNING: Gas scales linearly with watchedContracts.length.
     *      Keep watchlist ≤ MAX_WATCHED (20) and gasLimit ≥ 50_000 per watched contract.
     *      Do not emit events that match your own subscription filter — infinite loop risk.
     * @param emitter The Reactivity Precompile address (system event emitter).
     * @param eventTopics Topics from the BlockTick or Schedule system event (unused here).
     * @param data Encoded event data from the system event (unused here).
     */
    function _onEvent(
        address emitter,
        bytes32[] calldata eventTopics,
        bytes calldata data
    ) internal override {
        uint256 len = watchedContracts.length;
        // Cache block.number once — cheaper than reading in each iteration
        uint256 currentBlock = block.number;

        for (uint256 i = 0; i < len; i++) {
            emit RescanRequested(watchedContracts[i], currentBlock);
        }
    }

    // ─── Views ────────────────────────────────────────────────────────────────

    /**
     * @notice Returns all currently watched contract addresses.
     * @return Array of watched addresses in insertion order (swap-and-pop may alter order).
     */
    function getWatchedContracts() external view returns (address[] memory) {
        return watchedContracts;
    }

    /**
     * @notice Returns the current watchlist size.
     * @return Number of contracts currently being watched.
     */
    function watchlistSize() external view returns (uint256) {
        return watchedContracts.length;
    }
}
