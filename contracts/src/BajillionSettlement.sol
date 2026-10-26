// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.36;

import { LibBLS12381 as BLS } from "commonware/certificate/LibBLS12381.sol";
import { LibCodec } from "commonware/codec/LibCodec.sol";
import { AdmissionVerifier, CertificateVerifier } from "./verify/BajillionVerifiers.sol";
import { LibClearingCodec as Codec } from "./verify/LibClearingCodec.sol";
import { Ed25519Verifier } from "./verify/LibEd25519.sol";
import { BajillionChallenge } from "./BajillionChallenge.sol";
import { BajillionWithdrawals as Withdrawals } from "./BajillionWithdrawals.sol";
import { BajillionClaims as Claims } from "./BajillionClaims.sol";

/// @notice Minimal TIP-20 surface. TIP-20 tokens expose the ERC-20 transfer functions.
interface ITIP20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @title Bajillion settlement on Tempo
/// @notice A port of `SettlementChain` from Commonware's `commonware-clearing` crate
/// (clearing/src/bajillion/settlement.rs at commonwarexyz/monorepo
/// dd6d60cb44fb3dc05cee1efa06d957ce30df1340). Bajillion and the crate are Commonware's. This
/// contract is an embedding of their state machine: names, preconditions and error order follow
/// the Rust code, and every function cites the lines it ports.
///
/// Implemented: constructor, `deposit` (record_deposit), `queueWithdrawal`, `registerEpoch` with
/// chain-queued and operator-carried withdrawals, `admit`, `finalize`, `claimWithdrawal`,
/// `faultExpired`, `challenge` (challenge_encoded, adjudicated in the linked `BajillionChallenge`
/// library), and the liveness fence that every `now`-taking method observes first. Withdrawal
/// signatures are ZIP215 Ed25519, checked at intake and registration exactly where upstream checks
/// them. `HigherAckEntry` and terminal settlement come later.
///
/// Clock: `now` is `block.timestamp`, which Tempo keeps non-decreasing. The crate requires one
/// authenticated monotonic clock (settlement.rs:10) and does not fix its unit.
///
/// Liveness fence (settlement.rs:3-12): every method that takes `now` first observes expired
/// deadlines, and that fence may be its only state change even when the requested operation
/// fails. A revert would roll the fence back, so once this call has written the fence the contract
/// returns a `Status` and emits `HardFault` instead of reverting. When nothing was written it
/// reverts with the custom error for the same Rust variant.
///
/// Rust variant to Solidity mapping:
///
/// | Rust (settlement.rs:3159-3314, transition.rs:1855-1944) | Solidity |
/// |---|---|
/// | SettlementError::Deployment | `Deployment()` |
/// | SettlementError::OperatorMismatch | `OperatorMismatch()` |
/// | SettlementError::EpochSequence | `EpochSequence()` |
/// | SettlementError::StateAncestry | `StateAncestry()` / `Status.StateAncestry` |
/// | SettlementError::CommitteeMismatch | `CommitteeMismatch()` |
/// | SettlementError::BoundaryRoot | `BoundaryRoot()` |
/// | SettlementError::IntakeRange | `IntakeRange()` |
/// | SettlementError::IntakeOverflow | `IntakeOverflow()` |
/// | SettlementError::ZeroDeposit | `ZeroDeposit()` |
/// | SettlementError::DuplicateDeposit | unreachable: the contract assigns deposit ids itself |
/// | SettlementError::DepositCapacity | `DepositCapacity()` |
/// | SettlementError::DepositDeadlineOverflow | `DepositDeadlineOverflow()` |
/// | SettlementError::WithdrawalNoticeOrder | `WithdrawalNoticeOrder()` |
/// | SettlementError::DeadlineNotReached | `DeadlineNotReached()` |
/// | SettlementError::OperatorHardFaulted | `OperatorHardFaulted()` if the fault predates the call, else `Status.OperatorHardFaulted` |
/// | SettlementError::CustodyArithmetic | `CustodyArithmetic()` / `Status.CustodyArithmetic` |
/// | SettlementError::NoRegisteredEpoch | `NoRegisteredEpoch()` |
/// | SettlementError::EpochDeadlineOverflow | `EpochDeadlineOverflow()` |
/// | SettlementError::InvalidCertificate | `InvalidCertificate()` |
/// | SettlementError::NoPendingBatch | `NoPendingBatch()` / `Status.NoPendingBatch` |
/// | SettlementError::BatchInvalidated | `BatchInvalidated()` / `Status.BatchInvalidated` |
/// | SettlementError::ChallengeWindowOpen | `ChallengeWindowOpen()` / `Status.ChallengeWindowOpen` |
/// | SettlementError::EpochOverflow | `EpochOverflow()` / `Status.EpochOverflow` |
/// | SettlementError::Transition(EpochAnchor) | `TransitionEpochAnchor()` |
/// | SettlementError::Transition(HeaderRoot) | `TransitionHeaderRoot()` |
/// | SettlementError::Transition(BoundaryRoot) | `TransitionBoundaryRoot()` |
/// | SettlementError::Transition(CloseLimit) | `TransitionCloseLimit()` |
/// | SettlementError::Transition(LogRange) | `TransitionLogRange()` |
/// | SettlementError::Transition(WithdrawalOutputRoot) | `TransitionWithdrawalOutputRoot()` |
/// | SettlementError::Transition(LiabilityEquation) | `TransitionLiabilityEquation()` |
/// | SettlementError::Transition(LiabilityOverflow) | `TransitionLiabilityOverflow()` |
/// | SettlementError::Commitment(TooManyValues) | `DepositBatchEncoding()` |
/// | ClaimError::Unavailable | `ClaimUnavailable()` |
/// | ClaimError::Reserve | `ClaimReserve()` |
/// | ClaimError::Proof | `ClaimProof()` |
/// | admission::Error::InvalidCommitteeSize | `InvalidCommitteeSize()` |
/// | admission::Error::DuplicateValidator | `DuplicateValidator()` |
/// | panic in register_epoch (deposits exceed unpulled, settlement.rs:1304-1307) | `DepositAggregate()` |
/// | SettlementError::WithdrawalWitness | `WithdrawalWitness()` |
/// | SettlementError::DestinationTooLarge | `DestinationTooLarge()` |
/// | SettlementError::WithdrawalOpening | `WithdrawalOpening()` |
/// | SettlementError::WithdrawalBalance | `WithdrawalBalance()` |
/// | SettlementError::DuplicateWithdrawal | `DuplicateWithdrawal()` |
/// | SettlementError::DuplicateWithdrawalAuthorization | `DuplicateWithdrawalAuthorization()` |
/// | SettlementError::WithdrawalDeadlineTooSoon | `WithdrawalDeadlineTooSoon()` |
/// | SettlementError::WithdrawalDeadlineTooLate | `WithdrawalDeadlineTooLate()` |
/// | SettlementError::Boundary(WrongContext) | `BoundaryWrongContext()` |
/// | SettlementError::Boundary(InvalidWithdrawalSignature) | `BoundaryInvalidSignature()` |
/// | SettlementError::State(Proof) | `StateProof()` |
/// | SettlementError::AlreadyChallenged | `AlreadyChallenged()` |
/// | ChallengeError::Expired | `ChallengeExpired()` |
/// | ChallengeError::TooLarge | `ChallengeTooLarge()` |
/// | ChallengeError::HeaderRoot | `ChallengeHeaderRoot()` |
/// | ChallengeError::Codec | `ChallengeCodec()` |
/// | ChallengeError::LookupOrder | `ChallengeLookupOrder()` |
/// | ChallengeError::Activity | `ChallengeActivity()` |
/// | ChallengeError::Ack(InvalidPayerSignature) | `ChallengeInvalidPayerSignature()` |
/// | ChallengeError::Ack(InvalidOperatorSignature) | `ChallengeInvalidOperatorSignature()` |
/// | HigherAckEntry evidence (Ack(InfeasibleEntry), Vector, Commitment) | `ChallengeKindUnsupported()` |
/// | Any of the above after this call wrote the fence | `Status.Rejected` and `Rejected(selector)` |
/// | Hard-fault settlement variants | not in this pass |
///
/// Errors with no Rust counterpart are embedding checks: decoding (`*Encoding`), witnesses the
/// contract needs because it is not the Rust process (`CommitteeKeys`, point hints), fixed
/// storage capacities (`PipelineFull`, `InboxFull`), and asset transfer (`TransferFailed`,
/// `IneligibleDestination`).
contract BajillionSettlement {
    // ---------------------------------------------------------------------------------------
    // Types
    // ---------------------------------------------------------------------------------------

    /// @notice Result of a `now`-taking call. Anything but `Ok` means the call committed only the
    /// liveness fence and the requested operation did not happen.
    enum Status {
        Ok,
        OperatorHardFaulted,
        NoPendingBatch,
        BatchInvalidated,
        ChallengeWindowOpen,
        StateAncestry,
        EpochOverflow,
        CustodyArithmetic,
        /// The call wrote the fence, then its operation failed; `Rejected` carries the error.
        Rejected
    }

    /// @notice `challenge::Verdict` (challenge.rs:606-612) with the proven `ChallengeKind`.
    enum Verdict {
        NoContradiction,
        ProvenHigherAckDebit,
        ProvenHigherAckEntry,
        ProvenAckFork
    }

    /// @notice `HardFaultReason` tags, offset by one from settlement.rs:2277-2311 so zero means
    /// operating.
    enum FaultKind {
        None,
        ProvenChallenge,
        ExpiredDeposit,
        ExpiredWithdrawal,
        ExpiredRegistration
    }

    /// @notice `SettlementConfig` (settlement.rs:241-256). Every field is nonzero, as the Rust
    /// `NonZero` types require.
    struct SettlementConfig {
        uint64 admissionDelay;
        uint64 challengeDuration;
        uint64 depositInclusionTimeout;
        uint64 minimumWithdrawalNotice;
        uint64 maximumWithdrawalNotice;
        uint64 maxDestinationBytes;
        uint64 maxDepositIds;
    }

    /// @notice `Genesis` (settlement.rs:586-629), supplied by trusted setup.
    struct Genesis {
        bytes32 root;
        uint64 operations;
        uint64 liability;
    }

    /// @notice One committee member. `key` and `pop` are the crate's compressed encodings; the
    /// uncompressed hints are bound to them by `LibBLS12381Point`.
    struct Validator {
        bytes key;
        BLS.G2Point point;
        bytes pop;
        bytes popPoint;
    }

    struct DeploymentArgs {
        bytes32 deployment;
        bytes32 operator;
        uint64 expectedEpoch;
        Genesis genesis;
        SettlementConfig config;
        address asset;
        uint256 bond;
        bytes popNamespace;
        Validator[] committee;
        /// Outer byte bound passed to `challenge_encoded` (settlement.rs:1559-1572). The crate
        /// leaves it to the embedding.
        uint64 maxChallengeBytes;
    }

    /// @notice Arguments to `admit`, grouped to keep the stack shallow.
    /// @param header The 32-byte `transition::Header`.
    /// @param roots The 184-byte `RootBundle` encoding.
    /// @param certificate The crate's `multisig::Certificate<MinSig>` encoding.
    /// @param signature Uncompressed aggregate signature matching the certificate's compressed one.
    /// @param committee The registered G2 keys in certificate-index order.
    /// @param deposits The frontier's `DepositBatch` encoding.
    /// @param withdrawals The frontier's `WithdrawalBatch` encoding (empty in this pass).
    struct Admission {
        bytes32 header;
        bytes roots;
        uint64 withdrawalTotal;
        bytes certificate;
        bytes signature;
        BLS.G2Point[] committee;
        bytes deposits;
        bytes withdrawals;
    }

    /// @notice `LogHead` (logs.rs:168-176). Two slots.
    struct LogHead {
        bytes32 root;
        uint64 operations;
        uint64 floor;
    }

    /// @notice One registered or admitted epoch.
    /// @dev Epochs live in a ring of `EPOCH_RING` records keyed by `epoch % EPOCH_RING`. Tempo
    /// charges 250,000 gas for each storage slot that goes from zero to nonzero, so a record that
    /// is overwritten in place costs about 3,000 per slot after the ring's first lap. Records are
    /// never cleared, for the same reason; `status` and the deadlines are rewritten on reuse.
    /// Fields are packed so that each slot is written by one step of the lifecycle.
    struct Epoch {
        // Registration (EpochContext, transition.rs:492-499). The deployment, operator and
        // committee are immutable per deployment and are not stored per epoch.
        bytes32 anchor;
        bytes32 depositRoot;
        bytes32 withdrawalRoot;
        uint64[8] limits; // CloseLimits (transition.rs:356-365), two slots.
        uint64 epoch; // Guards against reading a stale ring record.
        uint64 floorActivity; // Floors captured pos registration (settlement.rs:1776-1781).
        uint64 floorPayouts;
        uint64 depositTotal;
        // Promotion (settlement.rs:1418-1440). Zero admission deadline means not yet promoted;
        // a promoted deadline is at least `admissionDelay > 0`.
        uint64 admissionDeadline;
        uint64 challengeDeadline;
        // Admission (settlement.rs:1523-1540).
        uint64 withdrawalTotal;
        uint8 status;
        uint8 challengeKind; // ChallengeKind tag (settlement.rs:2227-2233) when status is CHALLENGED.
        bytes32 batchId;
        bytes32 successorRoot;
        bytes32 activityRoot;
        bytes32 payoutRoot;
        uint64 activityOperations;
        uint64 activityFloor;
        uint64 payoutOperations;
        uint64 payoutFloor;
        uint64 rowsStart;
        uint64 rowsEnd;
        uint64 successorLiability;
        // keccak256 of the predecessor `Heads`, compared at finalization (settlement.rs:1647-1649).
        bytes32 predecessorLogs;
        // `earliest_withdrawal` of the registered batch (settlement.rs:431-439): its smallest
        // `(deadline, account)`, or zero deadline when the batch is empty. Deadlines are positive.
        uint64 withdrawalDeadline;
        bytes32 withdrawalAccount;
    }

    /// @notice One run of unpulled deposits sharing an inclusion deadline (settlement.rs:280-287).
    struct Run {
        uint64 end;
        uint64 deadline;
        bytes32 account;
    }

    /// @notice The parts of an `Epoch` that `epochRecord` returns.
    struct EpochView {
        bytes32 anchor;
        bytes32 batchId;
        uint8 status;
        uint8 challengeKind;
        uint64 admissionDeadline;
        uint64 challengeDeadline;
        uint64 withdrawalTotal;
        uint64 successorLiability;
        uint64 floorActivity;
        uint64 floorPayouts;
    }

    /// @dev The settlement-visible prefix the next frontier binds (settlement.rs:895-907, 1749-1770).
    struct Head {
        bytes32 stateRoot;
        LogHead activity;
        LogHead payouts;
        uint64 rowsStart;
        uint64 rowsEnd;
        uint64 liability;
    }

    /// @dev Decoded `RootBundle` (transition.rs:128-143).
    struct Roots {
        LogHead change;
        uint64 rowCount;
        LogHead outputs;
        bytes32 successor;
        uint64 successorOperations;
        uint64 successorSyncBoundary;
    }

    // ---------------------------------------------------------------------------------------
    // Errors
    // ---------------------------------------------------------------------------------------

    error Deployment();
    error OperatorMismatch();
    error EpochSequence();
    error StateAncestry();
    error CommitteeMismatch();
    error BoundaryRoot();
    error IntakeRange();
    error IntakeOverflow();
    error ZeroDeposit();
    error DepositCapacity();
    error DepositDeadlineOverflow();
    error WithdrawalNoticeOrder();
    error DeadlineNotReached();
    error OperatorHardFaulted();
    error CustodyArithmetic();
    error NoRegisteredEpoch();
    error EpochDeadlineOverflow();
    error InvalidCertificate();
    error NoPendingBatch();
    error BatchInvalidated();
    error ChallengeWindowOpen();
    error EpochOverflow();
    error TransitionEpochAnchor();
    error TransitionHeaderRoot();
    error TransitionBoundaryRoot();
    error TransitionCloseLimit();
    error TransitionLogRange();
    error TransitionWithdrawalOutputRoot();
    error TransitionLiabilityEquation();
    error TransitionLiabilityOverflow();
    error ClaimUnavailable();
    error ClaimReserve();
    error ClaimProof();
    error InvalidCommitteeSize();
    error DuplicateValidator();
    // Embedding errors with no Rust counterpart.
    error ZeroConfig();
    error InvalidOperatorKey();
    error NonCanonicalCommittee();
    error CommitteeEncoding();
    error InvalidProofOfPossession();
    error CommitteeKeys();
    error ContextEncoding();
    error RootsEncoding();
    error DepositBatchEncoding();
    error DepositAggregate();
    error ClaimEncoding();
    error IneligibleDestination();
    error PipelineFull();
    error InboxFull();
    error TransferFailed();
    // Challenge errors (settlement.rs:3285-3289, challenge.rs:731-759).
    error AlreadyChallenged();
    error ChallengeExpired();
    error ChallengeTooLarge();
    error ChallengeHeaderRoot();
    error ChallengeCodec();
    error ChallengeKindUnsupported();
    error ChallengeLookupOrder();
    error ChallengeActivity();
    error ChallengeInvalidPayerSignature();
    error ChallengeInvalidOperatorSignature();
    // Withdrawal errors (settlement.rs:3159-3314, boundary.rs:619-638, qmdb.rs `Error::Proof`).
    error WithdrawalWitness();
    error DestinationTooLarge();
    error WithdrawalOpening();
    error WithdrawalBalance();
    error DuplicateWithdrawal();
    error DuplicateWithdrawalAuthorization();
    error WithdrawalDeadlineTooSoon();
    error WithdrawalDeadlineTooLate();
    error BoundaryWrongContext();
    error BoundaryInvalidSignature();
    error StateProof();
    // Embedding errors: undecodable withdrawal or opening bytes, and a wrong list position hint.
    error WithdrawalEncoding();
    error StateOpeningEncoding();
    error WithdrawalOrder();

    // ---------------------------------------------------------------------------------------
    // Events
    // ---------------------------------------------------------------------------------------

    event Deposited(uint64 indexed index, bytes32 indexed account, uint64 amount);
    event WithdrawalQueued(uint64 indexed index, bytes32 indexed account, uint64 deadline);
    event EpochRegistered(uint64 indexed epoch, bytes32 anchor, uint64 pulledEnd);
    event EpochPromoted(uint64 indexed epoch, uint64 admissionDeadline, uint64 challengeDeadline);
    event Admitted(uint64 indexed epoch, bytes32 indexed batchId, bytes32 header);
    event Finalized(
        uint64 indexed epoch,
        bytes32 indexed batchId,
        bytes32 successorRoot,
        uint64 withdrawalTotal,
        uint64 custodyBalance,
        uint64 commitIndex
    );
    event WithdrawalClaimed(
        uint64 indexed index, address indexed destination, uint64 amount, uint64 rangeStart, uint64 rangeEnd
    );
    event ChallengeProven(uint64 indexed epoch, bytes32 indexed batchId, Verdict verdict, uint64 invalidatedThrough);
    /// @notice A call that wrote the fence then failed with `reason` (the custom error's selector).
    event Rejected(bytes4 reason);
    /// @param detail The account for an expired deposit or withdrawal, the anchor for an expired
    /// registration, or the batch id for a proven challenge.
    event HardFault(FaultKind kind, uint64 expiredAt, bytes32 detail, uint64 epoch, uint64 admissionFenceEpoch);

    // ---------------------------------------------------------------------------------------
    // Constants
    // ---------------------------------------------------------------------------------------

    bytes internal constant HEADER_ROOT_NAMESPACE = "_COMMONWARE_CLEARING_HEADER_ROOT"; // transition.rs:38
    bytes internal constant BATCH_ID_NAMESPACE = "_COMMONWARE_CLEARING_BATCH_ID"; // transition.rs:36
    bytes internal constant EPOCH_ANCHOR_NAMESPACE = "_COMMONWARE_CLEARING_EPOCH_ANCHOR"; // transition.rs:40
    bytes internal constant COMMITTEE_NAMESPACE = "_COMMONWARE_CLEARING_COMMITTEE"; // admission/certificate.rs:16

    /// @dev `mmr::Family::MAX_LEAVES` (storage/src/merkle/mmr/mod.rs:110).
    uint64 internal constant MMR_MAX_LEAVES = 1 << 62;
    /// @dev `mmb::Family::MAX_LEAVES` (storage/src/merkle/mmb/mod.rs:161).
    uint64 internal constant MMB_MAX_LEAVES = 0x4000_0000_0000_001E;
    /// @dev `commitment::MAX_VECTOR_LENGTH` (commitment.rs:28).
    uint256 internal constant MAX_VECTOR_LENGTH = 1 << 24;
    /// @dev `admission::MAX_COMMITTEE_SIZE` (admission/certificate.rs:19).
    uint256 internal constant MAX_COMMITTEE_SIZE = type(uint16).max;
    /// @dev `Opening` decodes at most `MAX_PROOF_DIGESTS_PER_ELEMENT * 2` digests (logs.rs:450-455,
    /// storage/src/merkle/proof.rs:189).
    uint256 internal constant MAX_OPENING_DIGESTS = 122 * 2;
    /// @dev Encoded sizes (protocol-notes.md section 1).
    uint256 internal constant EPOCH_CONTEXT_SIZE = 264;
    uint256 internal constant ROOT_BUNDLE_SIZE = 184;
    /// @dev Requests decoded from one withdrawal batch; the crate leaves the bound to the embedding.
    uint256 internal constant MAX_WITHDRAWAL_RECORDS = 1024;

    /// @dev Capacity of the epoch ring: registered plus admitted-but-unfinalized epochs. The crate
    /// bounds neither (settlement.rs:235-239); a fixed ring keeps storage reusable.
    uint256 public constant EPOCH_RING = 64;
    /// @dev Capacity of the inbox ring. At most `INBOX_RING - 1` deposits may be unpulled.
    uint256 public constant INBOX_RING = 1024;

    // ---------------------------------------------------------------------------------------
    // Immutable deployment
    // ---------------------------------------------------------------------------------------

    bytes32 public immutable deployment;
    bytes32 public immutable operator;
    /// @dev `Committee::commitment` (admission/certificate.rs:21-27, 78-80).
    bytes32 public immutable committeeCommitment;
    /// @dev keccak256 of the ABI-encoded uncompressed committee keys. Keys are 256 bytes each, so
    /// storing them would cost 8 new slots per validator on Tempo; `admit` takes them as calldata
    /// and checks this hash instead.
    bytes32 public immutable committeeKeysHash;
    uint256 public immutable committeeSize;
    uint256 public immutable quorum;
    address public immutable asset;
    /// @notice Operator bond, escrowed at deployment. This is our addition: `SettlementChain` has
    /// no bond. It is outside custody accounting and untouched in this pass.
    uint256 public immutable bond;
    /// @dev Root of the bootstrap log head `Heads::empty` (logs.rs:261-280): the keyless MMR root
    /// of one `Commit(None, 0)` operation, encoded `0x00 0x00 0x00`. Both logs share it.
    bytes32 public immutable bootstrapLogRoot;

    uint64 public immutable admissionDelay;
    uint64 public immutable challengeDuration;
    uint64 public immutable depositInclusionTimeout;
    uint64 public immutable minimumWithdrawalNotice;
    uint64 public immutable maximumWithdrawalNotice;
    uint64 public immutable maxDestinationBytes;
    uint64 public immutable maxDepositIds;
    uint64 public immutable maxChallengeBytes;

    // ---------------------------------------------------------------------------------------
    // State
    // ---------------------------------------------------------------------------------------

    // Finalized prefix (settlement.rs:653-658). Five slots, rewritten in place on each finalize.
    bytes32 public currentStateRoot;
    LogHead public finalizedActivity;
    LogHead public finalizedPayouts;

    // Epoch counters and custody. Packed four per slot because `admit` and `finalize` touch them
    // together.
    uint64 public expectedEpoch; // Next epoch to finalize (settlement.rs:678).
    uint64 public admittedEnd; // Next epoch to admit; the pipeline is [expectedEpoch, admittedEnd).
    uint64 public registeredEnd; // Next epoch to register; registered epochs are [admittedEnd, registeredEnd).
    uint64 public currentLiability;

    uint64 public custodyBalance;
    uint64 public claimableBalance;
    uint64 public unfinalizedDepositTotal;
    uint64 public finalizedRowsStart;

    uint64 public finalizedRowsEnd;
    uint64 public intake; // Inbox length (settlement.rs:662-663).
    uint64 public pulled; // First unpulled inbox index (settlement.rs:664-665).
    uint64 public depositCount; // Lifetime deposits, bounded by `maxDepositIds`.

    // Run ring indices (settlement.rs:669-671).
    uint64 public runHead;
    uint64 public runTail;

    // Permanent fault (settlement.rs:682-684). One slot plus one detail word.
    FaultKind public faultKind;
    uint64 public faultExpiredAt;
    uint64 public faultEpoch;
    uint64 public admissionFenceEpoch;
    bytes32 public faultDetail;
    /// @dev The earliest receipt-invalidated close (settlement.rs:684).
    bytes32 public invalidFrom;

    mapping(uint256 => Epoch) internal epochs;
    /// @dev Unadmitted deposit totals by account (settlement.rs:666-668). One slot per account.
    mapping(bytes32 => uint64) public pendingDeposits;
    /// @dev Inbox hash chain: `inboxChain[(i + 1) % INBOX_RING]` commits every deposit before
    /// index `i + 1`. The crate leaves per-deposit storage to the embedding (settlement.rs:14-17);
    /// one word per deposit in a reused ring is the cheapest record that still lets
    /// `registerEpoch` check the supplied aggregate exactly.
    mapping(uint256 => bytes32) internal inboxChain;
    /// @dev Runs live in a ring with the same capacity as the inbox, since every run holds at
    /// least one unpulled deposit.
    mapping(uint256 => Run) internal runs;
    /// @dev Claimed payout ranges, kept by the linked `BajillionClaims` library.
    Claims.State internal claimState;

    /// @dev Chain-queued withdrawals, replay ids and carried batches, kept by the linked
    /// `BajillionWithdrawals` library (see its `State`).
    Withdrawals.State internal withdrawalState;

    // ---------------------------------------------------------------------------------------
    // Constructor
    // ---------------------------------------------------------------------------------------

    /// @notice Create a deployment from trusted setup (settlement.rs:696-747). Every committee key
    /// must carry a valid MinSig proof of possession; one bad proof rejects the whole committee,
    /// as `Committee::new` requires (admission/certificate.rs:39-42).
    /// @dev The deployer must approve this contract's address for `genesis.liability + bond` of
    /// `asset` beforehand, so custody is funded atomically with deployment.
    constructor(DeploymentArgs memory d) {
        SettlementConfig memory c = d.config;
        if (
            c.admissionDelay == 0 || c.challengeDuration == 0 || c.depositInclusionTimeout == 0
                || c.minimumWithdrawalNotice == 0 || c.maximumWithdrawalNotice == 0 || c.maxDepositIds == 0
        ) revert ZeroConfig();
        if (d.expectedEpoch == type(uint64).max) revert EpochOverflow();
        if (c.maximumWithdrawalNotice < c.minimumWithdrawalNotice) revert WithdrawalNoticeOrder();
        // The operator is a `StrictVerifyingKey` upstream, so decoding rejects any other key
        // (cryptography/curve25519/src/signing.rs:403-415).
        if (!Ed25519Verifier.isStrictKey(d.operator)) revert InvalidOperatorKey();

        (bytes32 commitment, bytes32 keysHash, uint256 n) = _registerCommittee(d.committee, d.popNamespace);

        deployment = d.deployment;
        operator = d.operator;
        committeeCommitment = commitment;
        committeeKeysHash = keysHash;
        committeeSize = n;
        // `faults = (n - 1) / 3` and `quorum = faults + 1` (admission/certificate.rs:58-70,
        // utils/src/faults.rs:88-95).
        quorum = (n - 1) / 3 + 1;
        asset = d.asset;
        bond = d.bond;
        admissionDelay = c.admissionDelay;
        challengeDuration = c.challengeDuration;
        depositInclusionTimeout = c.depositInclusionTimeout;
        minimumWithdrawalNotice = c.minimumWithdrawalNotice;
        maximumWithdrawalNotice = c.maximumWithdrawalNotice;
        maxDestinationBytes = c.maxDestinationBytes;
        maxDepositIds = c.maxDepositIds;
        maxChallengeBytes = d.maxChallengeBytes;

        bytes32 bootstrap = sha256(abi.encodePacked(uint64(1), sha256(abi.encodePacked(uint64(0), hex"000000"))));
        bootstrapLogRoot = bootstrap;

        currentStateRoot = d.genesis.root;
        finalizedActivity = LogHead(bootstrap, 1, 0);
        finalizedPayouts = LogHead(bootstrap, 1, 0);
        currentLiability = d.genesis.liability;
        custodyBalance = d.genesis.liability;
        expectedEpoch = d.expectedEpoch;
        admittedEnd = d.expectedEpoch;
        registeredEnd = d.expectedEpoch;

        uint256 funding = uint256(d.genesis.liability) + d.bond;
        if (funding != 0 && !ITIP20(d.asset).transferFrom(msg.sender, address(this), funding)) {
            revert TransferFailed();
        }
    }

    /// @dev Validate the canonical `3f + 1` committee, each key's hint and proof of possession, and
    /// derive its commitment. Callers supply keys in canonical order (strictly increasing
    /// compressed bytes); `Committee::new` sorts instead (utils/src/ordered.rs:142-148), so a
    /// different order is rejected rather than silently reordered.
    function _registerCommittee(Validator[] memory committee, bytes memory popNamespace)
        private
        view
        returns (bytes32 commitment, bytes32 keysHash, uint256 n)
    {
        n = committee.length;
        // admission/certificate.rs:132-134.
        if (n == 0 || n > MAX_COMMITTEE_SIZE || (n - 1) % 3 != 0) revert InvalidCommitteeSize();
        // forge-lint: disable-next-line(unsafe-typecast) bounded by the checks above
        bytes memory encoded = LibCodec.encodeVarint(uint64(n));
        BLS.G2Point[] memory points = new BLS.G2Point[](n);
        for (uint256 i; i < n; ++i) {
            Validator memory v = committee[i];
            (bool keyOk, bool popOk) =
                CertificateVerifier.verifyValidator(v.key, v.point, v.pop, v.popPoint, popNamespace);
            if (!keyOk) revert CommitteeEncoding();
            if (i > 0) {
                int256 order = _compare96(committee[i - 1].key, v.key);
                if (order == 0) revert DuplicateValidator();
                if (order > 0) revert NonCanonicalCommittee();
            }
            if (!popOk) revert InvalidProofOfPossession();
            points[i] = v.point;
            encoded = bytes.concat(encoded, v.key);
        }
        commitment = sha256(bytes.concat(COMMITTEE_NAMESPACE, encoded));
        keysHash = keccak256(abi.encode(points));
    }

    // ---------------------------------------------------------------------------------------
    // Liveness fence
    // ---------------------------------------------------------------------------------------

    /// @notice Permanently fence the deployment after its earliest liveness deadline
    /// (settlement.rs:1784-1794). Reverts leave no state, since nothing is written before them.
    function faultExpired() external returns (FaultKind) {
        if (faultKind != FaultKind.None) revert OperatorHardFaulted();
        (FaultKind kind, uint64 expiredAt, bytes32 detail, uint64 epoch) = _expiredReason(_now());
        if (kind == FaultKind.None) revert DeadlineNotReached();
        _enterHardFault(kind, expiredAt, detail, epoch);
        return kind;
    }

    /// @dev `observe_time` (settlement.rs:861-874). Returns true when this call wrote the fence.
    /// Replay-id pruning needs no write here: see `withdrawalReplayExpiry`.
    function _observeTime(uint64 now_) private returns (bool fenced) {
        if (faultKind != FaultKind.None) return false;
        (FaultKind kind, uint64 expiredAt, bytes32 detail, uint64 epoch) = _expiredReason(now_);
        if (kind == FaultKind.None) return false;
        _enterHardFault(kind, expiredAt, detail, epoch);
        return true;
    }

    /// @dev `ensure_operating_at` (settlement.rs:876-879). Returns true when this call wrote the
    /// fence, so the caller must return a status instead of reverting. Reverts when the fault
    /// predates the call.
    function _ensureOperatingAt(uint64 now_) private returns (bool fenced) {
        fenced = _observeTime(now_);
        if (!fenced && faultKind != FaultKind.None) revert OperatorHardFaulted();
    }

    /// @dev `expired_reason` (settlement.rs:769-836).
    function _expiredReason(uint64 now_)
        private
        view
        returns (FaultKind kind, uint64 expiredAt, bytes32 detail, uint64 epoch)
    {
        // Every deposit shares one timeout, so the front run holds the earliest deadline.
        bool depositExpired;
        Run storage front = runs[runHead % INBOX_RING];
        if (runHead < runTail && now_ >= front.deadline) depositExpired = true;

        // Withdrawal attribution wins when both intake obligations expire together.
        (uint64 wDeadline, bytes32 wAccount) = _earliestWithdrawalDeadline();
        bool withdrawalExpired = wDeadline != 0 && now_ >= wDeadline;
        FaultKind intakeKind;
        uint64 intakeDeadline;
        bytes32 intakeAccount;
        if (withdrawalExpired && (!depositExpired || wDeadline <= front.deadline)) {
            (intakeKind, intakeDeadline, intakeAccount) = (FaultKind.ExpiredWithdrawal, wDeadline, wAccount);
        } else if (depositExpired) {
            (intakeKind, intakeDeadline, intakeAccount) = (FaultKind.ExpiredDeposit, front.deadline, front.account);
        }

        bool registration;
        uint64 firstExpired;
        Epoch storage frontier = epochs[admittedEnd % EPOCH_RING];
        // A live frontier is always promoted; the zero check only guards a stale ring record.
        if (registeredEnd > admittedEnd && frontier.admissionDeadline != 0 && now_ > frontier.admissionDeadline) {
            registration = true;
            // A later timestamp was observed, so the deadline is below u64::MAX.
            firstExpired = frontier.admissionDeadline + 1;
        }

        // At a shared first-fault instant the registration reason wins (settlement.rs:827-835).
        if (registration && (intakeKind == FaultKind.None || firstExpired <= intakeDeadline)) {
            return (FaultKind.ExpiredRegistration, frontier.admissionDeadline, frontier.anchor, admittedEnd);
        }
        return (intakeKind, intakeDeadline, intakeAccount, 0);
    }

    /// @dev `earliest_withdrawal_deadline` (settlement.rs:756-767): the smallest
    /// `(deadline, account)` over chain-queued requests and admitted unfinalized closes. Requests
    /// carried only by registrations are not counted, as upstream. Zero deadline when none.
    function _earliestWithdrawalDeadline() private view returns (uint64 deadline, bytes32 account) {
        account = withdrawalState.head;
        if (account != 0) deadline = withdrawalState.pending[account].deadline;
        for (uint64 e = expectedEpoch; e < admittedEnd; ++e) {
            Epoch storage rec = epochs[e % EPOCH_RING];
            uint64 d = rec.withdrawalDeadline;
            if (d != 0 && (deadline == 0 || Withdrawals._before(d, rec.withdrawalAccount, deadline, account))) {
                (deadline, account) = (d, rec.withdrawalAccount);
            }
        }
    }

    /// @dev `enter_hard_fault` (settlement.rs:838-859): fence admission at the next admission
    /// epoch, drop the frontier and every queued registration, and clear deposit runs. Pulled but
    /// unadmitted deposits stay in `pendingDeposits` for refunds.
    function _enterHardFault(FaultKind kind, uint64 expiredAt, bytes32 detail, uint64 epoch) private {
        if (faultKind != FaultKind.None) return;
        uint64 fence = admittedEnd;
        admissionFenceEpoch = fence;
        faultKind = kind;
        faultExpiredAt = expiredAt;
        faultDetail = detail;
        faultEpoch = epoch;
        registeredEnd = fence;
        runHead = runTail;
        emit HardFault(kind, expiredAt, detail, epoch, fence);
    }

    // ---------------------------------------------------------------------------------------
    // Deposits
    // ---------------------------------------------------------------------------------------

    /// @notice Record one deposit for a 32-byte clearing account and pull its tokens
    /// (`record_deposit`, settlement.rs:983-1055). The contract is the deposit source, so the
    /// inbox index is the deposit id and `DuplicateDeposit` cannot occur.
    function deposit(bytes32 account, uint64 amount) external returns (Status, uint64 index) {
        uint64 now_ = _now();
        if (_ensureOperatingAt(now_)) return (Status.OperatorHardFaulted, 0);
        if (amount == 0) revert ZeroDeposit();
        if (depositCount >= maxDepositIds) revert DepositCapacity();
        if (uint256(now_) + depositInclusionTimeout > type(uint64).max) revert DepositDeadlineOverflow();
        uint64 deadline = now_ + depositInclusionTimeout;
        if (uint256(pendingDeposits[account]) + amount > type(uint64).max) revert CustodyArithmetic();
        // Leave room for deposit inclusion and a later account exit.
        if (uint256(registeredEnd) + 3 > type(uint64).max) revert EpochOverflow();
        uint256 custody = uint256(custodyBalance) + amount;
        if (custody > type(uint64).max || uint256(claimableBalance) + custody > type(uint64).max) {
            revert CustodyArithmetic();
        }
        if (uint256(unfinalizedDepositTotal) + amount > type(uint64).max) revert CustodyArithmetic();
        index = intake;
        if (index == type(uint64).max) revert IntakeOverflow();
        if (index - pulled >= INBOX_RING - 1) revert InboxFull();

        // Deposits recorded at one instant share a deadline and extend one run.
        if (runHead < runTail && runs[(runTail - 1) % INBOX_RING].deadline == deadline) {
            Run storage last = runs[(runTail - 1) % INBOX_RING];
            last.end = index + 1;
            last.account = account;
        } else {
            runs[runTail % INBOX_RING] = Run(index + 1, deadline, account);
            ++runTail;
        }
        pendingDeposits[account] += amount;
        ++depositCount;
        // forge-lint: disable-next-line(unsafe-typecast) bounded by the checks above
        custodyBalance = uint64(custody);
        unfinalizedDepositTotal += amount;
        inboxChain[(uint256(index) + 1) % INBOX_RING] =
            keccak256(abi.encodePacked(inboxChain[index % INBOX_RING], account, amount));
        intake = index + 1;
        emit Deposited(index, account, amount);

        if (!ITIP20(asset).transferFrom(msg.sender, address(this), amount)) revert TransferFailed();
        return (Status.Ok, index);
    }

    // ---------------------------------------------------------------------------------------
    // Withdrawals
    // ---------------------------------------------------------------------------------------

    /// @notice Queue one signed withdrawal against the finalized account balance
    /// (`queue_withdrawal`, settlement.rs:1129-1188) and return its inbox index.
    /// @param request The crate's `SignedWithdrawal` encoding.
    /// @param opening The crate's `StateOpening` encoding at the finalized state root.
    /// @param predecessor The account after which the request sorts in the pending list by
    /// `(deadline, account)`, or zero to insert at the head. The contract checks it in O(1).
    /// @dev Both encodings are decoded before time is observed, as the crate decodes them before
    /// the call, so undecodable bytes revert without the fence.
    function queueWithdrawal(bytes calldata request, bytes calldata opening, bytes32 predecessor)
        external
        returns (Status, uint64 index)
    {
        (bytes32 account, uint64 deadline) = Withdrawals.decodeQueued(request, opening, maxDestinationBytes);
        uint64 now_ = _now();
        if (_ensureOperatingAt(now_)) return (Status.OperatorHardFaulted, 0);
        index = intake;
        Withdrawals.queue(
            withdrawalState,
            _withdrawalConfig(),
            _window(),
            now_,
            currentStateRoot,
            request,
            opening,
            predecessor,
            index
        );
        if (index == type(uint64).max) revert IntakeOverflow();
        if (index - pulled >= INBOX_RING - 1) revert InboxFull();
        // A withdrawal occupies one inbox index. Its chain entry carries amount zero, which no
        // deposit can (`ZeroDeposit`), so the registration witness tells the two apart.
        inboxChain[(uint256(index) + 1) % INBOX_RING] =
            keccak256(abi.encodePacked(inboxChain[index % INBOX_RING], account, uint64(0)));
        intake = index + 1;
        emit WithdrawalQueued(index, account, deadline);
        return (Status.Ok, index);
    }

    function _withdrawalConfig() private view returns (Withdrawals.Config memory) {
        return Withdrawals.Config(deployment, minimumWithdrawalNotice, maximumWithdrawalNotice, maxDestinationBytes);
    }

    function _window() private view returns (Withdrawals.Window memory) {
        return Withdrawals.Window(expectedEpoch, admittedEnd, registeredEnd);
    }

    // ---------------------------------------------------------------------------------------
    // Registration
    // ---------------------------------------------------------------------------------------

    /// @notice Register the next epoch and pull the inbox up to `end` (`register_epoch`,
    /// settlement.rs:1251-1414).
    /// @param context The crate's 264-byte `EpochContext` encoding.
    /// @param deposits The `DepositBatch` encoding: the per-account aggregate of the pulled deposits.
    /// @param withdrawals The `WithdrawalBatch` encoding: every uncarried chain-queued request the
    /// pull reaches, verbatim, plus any operator-carried extras.
    /// @param pulledDeposits The inbox entries at indices `[pulled, end)`, packed as
    /// `account || amount` (40 bytes each), checked against the inbox hash chain. A deposit has a
    /// positive amount; a chain-queued withdrawal has amount zero. The crate trusts the embedding
    /// to supply the exact deposit aggregate and the owed withdrawals; this witness is how the
    /// contract checks both.
    function registerEpoch(
        bytes calldata context,
        uint64 end,
        bytes calldata deposits,
        bytes calldata withdrawals,
        bytes calldata pulledDeposits
    ) external returns (Status) {
        uint64 now_ = _now();
        if (_ensureOperatingAt(now_)) return Status.OperatorHardFaulted;
        if (context.length != EPOCH_CONTEXT_SIZE) revert ContextEncoding();
        if (Codec.readBytes32(context, 72) != deployment) revert Deployment();
        if (Codec.readBytes32(context, 40) != operator) revert OperatorMismatch();
        uint64 epoch = Codec.readU64(context, 32);
        if (epoch != registeredEnd) revert EpochSequence();
        if (epoch == type(uint64).max) revert EpochOverflow();
        if (uint256(epoch) - expectedEpoch >= EPOCH_RING) revert PipelineFull();
        if (Codec.readBytes32(context, 232) != committeeCommitment) revert CommitteeMismatch();
        if (end < pulled || end > intake) revert IntakeRange();

        (bytes calldata records, uint256 count, uint64 depositTotal) = _decodeDeposits(deposits);
        (bytes32 batchWithdrawalRoot, uint256 withdrawalCount) = _withdrawalBoundary(withdrawals);
        bytes32 depositRoot = Codec.readBytes32(context, 104);
        bytes32 withdrawalRoot = Codec.readBytes32(context, 136);
        if (depositRoot != AdmissionVerifier.depositRoot(records, count) || withdrawalRoot != batchWithdrawalRoot) {
            revert BoundaryRoot();
        }
        bytes calldata limits = context[168:232];
        if (Codec.readBytes32(context, 0) != _anchor(epoch, depositRoot, withdrawalRoot, limits)) {
            revert TransitionEpochAnchor();
        }
        (bytes32[] memory owedAccounts, uint64[] memory owedIndices) =
            _checkPulledAggregate(end, records, count, pulledDeposits);
        (uint64 admissionDeadline, uint64 challengeDeadline) = _frontierDeadlines(now_);
        uint64 withdrawalDeadline;
        bytes32 withdrawalAccount;
        if (withdrawalCount != 0 || owedAccounts.length != 0) {
            (withdrawalDeadline, withdrawalAccount) = Withdrawals.register(
                withdrawalState,
                _withdrawalConfig(),
                _window(),
                now_,
                withdrawals,
                MAX_WITHDRAWAL_RECORDS,
                owedAccounts,
                owedIndices,
                _latestChallengeDeadline(challengeDeadline)
            );
        }

        Epoch storage rec = epochs[epoch % EPOCH_RING];
        rec.anchor = Codec.readBytes32(context, 0);
        rec.depositRoot = depositRoot;
        rec.withdrawalRoot = withdrawalRoot;
        for (uint256 i; i < 8; ++i) {
            rec.limits[i] = Codec.readU64(limits, i * 8);
        }
        rec.epoch = epoch;
        // `registration_floors` (settlement.rs:1776-1781); finalized operations are always >= 1.
        rec.floorActivity = finalizedActivity.operations - 1;
        rec.floorPayouts = finalizedPayouts.operations - 1;
        rec.depositTotal = depositTotal;
        rec.admissionDeadline = 0;
        rec.challengeDeadline = 0;
        rec.withdrawalTotal = 0;
        rec.status = REGISTERED;
        rec.withdrawalDeadline = withdrawalDeadline;
        rec.withdrawalAccount = withdrawalAccount;

        // Pulled deposits carry no inclusion deadline. A run the pull splits keeps its deadline.
        while (runHead < runTail && runs[runHead % INBOX_RING].end <= end) {
            ++runHead;
        }
        pulled = end;
        registeredEnd = epoch + 1;
        emit EpochRegistered(epoch, rec.anchor, end);
        _promote(admissionDeadline, challengeDeadline);
        return Status.Ok;
    }

    uint8 internal constant REGISTERED = 1;
    uint8 internal constant PENDING = 2;
    uint8 internal constant CHALLENGED = 3;
    uint8 internal constant INVALIDATED = 4;

    /// @dev `promote` (settlement.rs:1418-1440). The predecessor fields are not copied here: the
    /// head cannot change between promotion and admission (only the frontier can be admitted, and
    /// finalization pops the front without changing the back's values), so `admit` reads the same
    /// values from `_head()`.
    function _promote(uint64 admissionDeadline, uint64 challengeDeadline) private {
        if (faultKind != FaultKind.None || registeredEnd <= admittedEnd) return;
        Epoch storage frontier = epochs[admittedEnd % EPOCH_RING];
        if (frontier.admissionDeadline != 0) return;
        frontier.admissionDeadline = admissionDeadline;
        frontier.challengeDeadline = challengeDeadline;
        emit EpochPromoted(admittedEnd, admissionDeadline, challengeDeadline);
    }

    /// @dev `frontier_deadlines` (settlement.rs:883-893). The challenge deadline stays below
    /// u64::MAX so one later tick exists for finalization or expiry.
    function _frontierDeadlines(uint64 now_) private view returns (uint64 admissionAt, uint64 challengeAt) {
        uint256 a = uint256(now_) + admissionDelay;
        uint256 c = a + challengeDuration;
        if (a > type(uint64).max || c >= type(uint64).max) revert EpochDeadlineOverflow();
        // forge-lint: disable-next-line(unsafe-typecast) bounded by the checks above
        return (uint64(a), uint64(c));
    }

    /// @dev Check that `records` is exactly the per-account aggregate of the deposits at
    /// `[pulled, end)`, and return the chain-queued withdrawals at those indices. Replaying the
    /// inbox chain authenticates `pulledDeposits`; the aggregate must then match record for record.
    /// Rust asserts only `<=` (settlement.rs:1290-1308) because it cannot see individual deposits;
    /// the contract can, so it requires equality.
    function _checkPulledAggregate(uint64 end, bytes calldata records, uint256 count, bytes calldata pulledDeposits)
        private
        view
        returns (bytes32[] memory owedAccounts, uint64[] memory owedIndices)
    {
        if (pulledDeposits.length != uint256(end - pulled) * 40) revert DepositAggregate();
        bool ok;
        bytes32 chain;
        (ok, chain, owedAccounts, owedIndices) =
            AdmissionVerifier.pulledAggregate(records, count, pulledDeposits, inboxChain[pulled % INBOX_RING], pulled);
        if (!ok || chain != inboxChain[end % INBOX_RING]) revert DepositAggregate();
    }

    /// @dev The latest challenge deadline over the pipeline, the frontier and `challengeDeadline`.
    function _latestChallengeDeadline(uint64 challengeDeadline) private view returns (uint64 latest) {
        latest = challengeDeadline;
        uint64 last = registeredEnd > admittedEnd ? admittedEnd + 1 : admittedEnd;
        for (uint64 e = expectedEpoch; e < last; ++e) {
            uint64 d = epochs[e % EPOCH_RING].challengeDeadline;
            if (d > latest) latest = d;
        }
    }

    // ---------------------------------------------------------------------------------------
    // Admission
    // ---------------------------------------------------------------------------------------

    /// @notice Admit the frontier's header, root witness and certificate (`admit`,
    /// settlement.rs:1446-1545).
    function admit(Admission calldata a) external returns (Status, bytes32 batchId) {
        uint64 now_ = _now();
        if (_ensureOperatingAt(now_)) return (Status.OperatorHardFaulted, bytes32(0));
        if (registeredEnd <= admittedEnd) revert NoRegisteredEpoch();
        uint64 epoch = admittedEnd;
        Epoch storage rec = epochs[epoch % EPOCH_RING];
        Roots memory roots = _decodeRoots(a.roots);
        Head memory hd = _head();

        // `validate_header` (transition.rs:1758-1769): `Header::verify` recomputes the anchor and
        // the header (transition.rs:320-328).
        bytes memory limits = _limits(rec);
        if (
            rec.anchor != _anchor(epoch, rec.depositRoot, rec.withdrawalRoot, limits)
                || a.header
                    != sha256(
                        abi.encodePacked(
                            HEADER_ROOT_NAMESPACE, _closeContext(rec, epoch, limits, hd), a.roots, a.withdrawalTotal
                        )
                    )
        ) revert TransitionHeaderRoot();
        _verifyCertificate(a);

        // `validate_close_amounts` (transition.rs:1771-1805).
        (uint64 successorLiability, uint256 withdrawalCount) = _validateCloseAmounts(rec, epoch, limits, hd, roots, a);
        bool promotion = registeredEnd > epoch + 1;
        uint64 admissionDeadline;
        uint64 challengeDeadline;
        if (promotion) (admissionDeadline, challengeDeadline) = _frontierDeadlines(now_);

        batchId = sha256(abi.encodePacked(BATCH_ID_NAMESPACE, a.header));
        // Registration pulled only recorded deposits, and only admission reduces their totals.
        (bytes calldata records, uint256 count,) = _decodeDeposits(a.deposits);
        for (uint256 i; i < count; ++i) {
            pendingDeposits[Codec.readBytes32(records, i * 40)] -= Codec.readU64(records, i * 40 + 32);
        }
        // The admitted batch retires the chain-queued requests it carries and consumes every
        // request's replay id until its deadline (settlement.rs:1504-1522).
        if (withdrawalCount != 0) {
            Withdrawals.retire(withdrawalState, a.withdrawals, MAX_WITHDRAWAL_RECORDS, maxDestinationBytes);
        }
        rec.withdrawalTotal = a.withdrawalTotal;
        rec.status = PENDING;
        rec.batchId = batchId;
        rec.successorRoot = roots.successor;
        rec.activityRoot = roots.change.root;
        rec.payoutRoot = roots.outputs.root;
        rec.activityOperations = roots.change.operations;
        rec.activityFloor = roots.change.floor;
        rec.payoutOperations = roots.outputs.operations;
        rec.payoutFloor = roots.outputs.floor;
        rec.rowsStart = hd.activity.operations;
        rec.rowsEnd = hd.activity.operations + roots.rowCount;
        rec.successorLiability = successorLiability;
        rec.predecessorLogs = _logsHash(hd.activity, hd.payouts);
        admittedEnd = epoch + 1;
        emit Admitted(epoch, batchId, a.header);
        if (promotion) _promote(admissionDeadline, challengeDeadline);
        return (Status.Ok, batchId);
    }

    /// @dev `bls12381::Scheme::verify` (admission/certificate.rs:359-386) on the crate's
    /// certificate bytes: `u64 BE bit count || ceil(n/8) bitmap bytes || 48-byte compressed G1`
    /// (cryptography/src/bls12381/certificate/multisig/mod.rs:363-368, utils/src/bitmap/mod.rs:860-870).
    /// The bit count must equal `n`; `verifyMinSig` checks the bitmap length, unused high bits and
    /// popcount `>= q`. The uncompressed hint must compress to the certificate's signature.
    function _verifyCertificate(Admission calldata a) private view {
        if (keccak256(abi.encode(a.committee)) != committeeKeysHash) revert CommitteeKeys();
        if (!CertificateVerifier.verifyCertificate(a.header, a.certificate, a.signature, a.committee, quorum)) {
            revert InvalidCertificate();
        }
    }

    /// @dev `validate_close_amounts` (transition.rs:1771-1805), including `validate_boundary_roots`
    /// (transition.rs:1806-1820) and `RootBundle::activity_range` (transition.rs:154-186).
    function _validateCloseAmounts(
        Epoch storage rec,
        uint64 epoch,
        bytes memory limits,
        Head memory hd,
        Roots memory roots,
        Admission calldata a
    ) private view returns (uint64, uint256 withdrawalCount) {
        if (rec.anchor != _anchor(epoch, rec.depositRoot, rec.withdrawalRoot, limits)) {
            revert TransitionEpochAnchor();
        }
        (bytes calldata records, uint256 count, uint64 depositTotal) = _decodeDeposits(a.deposits);
        bytes32 withdrawalRoot;
        (withdrawalRoot, withdrawalCount) = _withdrawalBoundary(a.withdrawals);
        if (AdmissionVerifier.depositRoot(records, count) != rec.depositRoot || withdrawalRoot != rec.withdrawalRoot) {
            revert TransitionBoundaryRoot();
        }
        (bytes4 err, uint64 successorLiability) = AdmissionVerifier.closeBounds(
            AdmissionVerifier.CloseBounds({
                withdrawalTotal: a.withdrawalTotal,
                maxRows: rec.limits[1],
                maxTotalEntries: rec.limits[4],
                maxWithdrawalTotal: rec.limits[7],
                floorActivity: rec.floorActivity,
                floorPayouts: rec.floorPayouts,
                headActivityOperations: hd.activity.operations,
                headActivityFloor: hd.activity.floor,
                headPayoutsOperations: hd.payouts.operations,
                headPayoutsFloor: hd.payouts.floor,
                headLiability: hd.liability,
                depositTotal: depositTotal,
                withdrawalCount: withdrawalCount,
                changeOperations: roots.change.operations,
                changeFloor: roots.change.floor,
                rowCount: roots.rowCount,
                outputOperations: roots.outputs.operations,
                outputFloor: roots.outputs.floor,
                successorOperations: roots.successorOperations,
                successorSyncBoundary: roots.successorSyncBoundary
            })
        );
        if (err != bytes4(0)) _revertWith(err);
        return (successorLiability, withdrawalCount);
    }

    /// @dev Revert with a bare custom-error selector returned by a linked library.
    function _revertWith(bytes4 err) private pure {
        assembly ("memory-safe") {
            mstore(0, err)
            revert(0, 4)
        }
    }

    // ---------------------------------------------------------------------------------------
    // Finalization
    // ---------------------------------------------------------------------------------------

    /// @notice Finalize the pipeline front after its inclusive challenge window (`finalize`,
    /// settlement.rs:1621-1701), and insert its trailing commit location into the claimed ranges
    /// in the same transaction (settlement.rs:1616-1620). Finalization continues after a fault,
    /// so the pre-fault prefix still settles.
    function finalize() external returns (Status) {
        uint64 now_ = _now();
        bool fenced = _observeTime(now_);
        uint64 epoch = expectedEpoch;
        if (admittedEnd == epoch) return _reject(fenced, Status.NoPendingBatch);
        if (epoch == type(uint64).max) return _reject(fenced, Status.EpochOverflow);
        Epoch storage rec = epochs[epoch % EPOCH_RING];
        if (rec.status != PENDING) return _reject(fenced, Status.BatchInvalidated);
        if (now_ <= rec.challengeDeadline) return _reject(fenced, Status.ChallengeWindowOpen);
        LogHead memory payouts = finalizedPayouts;
        if (rec.predecessorLogs != _logsHash(finalizedActivity, payouts)) {
            return _reject(fenced, Status.StateAncestry);
        }
        uint64 commitIndex = rec.payoutOperations - 1;
        if (commitIndex < payouts.operations) return _reject(fenced, Status.StateAncestry);

        uint64 withdrawalTotal = rec.withdrawalTotal;
        if (
            uint256(claimableBalance) + withdrawalTotal > type(uint64).max || custodyBalance < withdrawalTotal
                || unfinalizedDepositTotal < rec.depositTotal
        ) return _reject(fenced, Status.CustodyArithmetic);

        currentStateRoot = rec.successorRoot;
        currentLiability = rec.successorLiability;
        custodyBalance -= withdrawalTotal;
        claimableBalance += withdrawalTotal;
        unfinalizedDepositTotal -= rec.depositTotal;
        finalizedActivity = LogHead(rec.activityRoot, rec.activityOperations, rec.activityFloor);
        finalizedPayouts = LogHead(rec.payoutRoot, rec.payoutOperations, rec.payoutFloor);
        finalizedRowsStart = rec.rowsStart;
        finalizedRowsEnd = rec.rowsEnd;
        expectedEpoch = epoch + 1;
        // Every claimed range ends at or below the old payout count, which is at most
        // `commitIndex`, so the commit always extends the last range and this cannot fail.
        if (!Claims.insertCommit(claimState, commitIndex)) revert StateAncestry();
        emit Finalized(epoch, rec.batchId, rec.successorRoot, withdrawalTotal, custodyBalance, commitIndex);
        return Status.Ok;
    }

    // ---------------------------------------------------------------------------------------
    // Challenges
    // ---------------------------------------------------------------------------------------

    /// @notice Adjudicate one encoded challenge against an admitted close through its inclusive
    /// challenge deadline (`challenge_encoded`, settlement.rs:1559-1614).
    /// @param batchId The target's `BatchId`.
    /// @param context The target's 448-byte `CloseContext`, as published at admission.
    /// @param roots The target's 184-byte `RootBundle`.
    /// @param withdrawalTotal The target's certified withdrawal total.
    /// @param encoded The crate's `Challenge` encoding.
    /// @dev The contract stores only the batch id, so the caller supplies the context and roots;
    /// recomputing the header from them and matching the batch id is the check upstream performs
    /// in `adjudicate` (challenge.rs:631-633). A proven challenge marks the target challenged and
    /// every later pending close invalidated, then fences the deployment into a hard fault. Earlier
    /// pending closes can still finalize. Upstream has no bond, so nothing is slashed here.
    /// Malformed evidence changes no state beyond the liveness fence this call observes first.
    function challenge(
        bytes32 batchId,
        bytes calldata context,
        bytes calldata roots,
        uint64 withdrawalTotal,
        bytes calldata encoded
    ) external returns (Status, Verdict) {
        uint64 now_ = _now();
        bool fenced = _observeTime(now_);
        if (encoded.length > maxChallengeBytes) return _rejectChallenge(fenced, ChallengeTooLarge.selector);
        bytes4 err = BajillionChallenge.decode(encoded);
        if (err != bytes4(0)) return _rejectChallenge(fenced, err);

        // Find the admitted close (settlement.rs:1583-1596).
        uint64 epoch = expectedEpoch;
        while (epoch < admittedEnd && epochs[epoch % EPOCH_RING].batchId != batchId) {
            ++epoch;
        }
        if (epoch == admittedEnd) return _rejectChallenge(fenced, NoPendingBatch.selector);
        Epoch storage rec = epochs[epoch % EPOCH_RING];
        if (rec.status == CHALLENGED) return _rejectChallenge(fenced, AlreadyChallenged.selector);
        if (rec.status == INVALIDATED) return _rejectChallenge(fenced, BatchInvalidated.selector);
        if (now_ > rec.challengeDeadline) return _rejectChallenge(fenced, ChallengeExpired.selector);

        bool proven;
        uint8 kind;
        (err, proven, kind) = BajillionChallenge.adjudicate(batchId, operator, context, roots, withdrawalTotal, encoded);
        if (err != bytes4(0)) return _rejectChallenge(fenced, err);
        if (!proven) return (Status.Ok, Verdict.NoContradiction);

        rec.status = CHALLENGED;
        rec.challengeKind = kind;
        for (uint64 e = epoch + 1; e < admittedEnd; ++e) {
            epochs[e % EPOCH_RING].status = INVALIDATED;
        }
        invalidFrom = batchId;
        Verdict verdict = Verdict(kind + 1);
        emit ChallengeProven(epoch, batchId, verdict, admittedEnd - 1);
        _enterHardFault(FaultKind.ProvenChallenge, 0, batchId, epoch);
        return (Status.Ok, verdict);
    }

    /// @dev Return a `Rejected` status if this call wrote the fence; otherwise revert with `err`.
    function _rejectChallenge(bool fenced, bytes4 err) private returns (Status, Verdict) {
        if (!fenced) _revertWith(err);
        emit Rejected(err);
        return (Status.Rejected, Verdict.NoContradiction);
    }

    /// @dev Return `status` if this call wrote the fence; otherwise revert with its error.
    function _reject(bool fenced, Status status) private pure returns (Status) {
        if (fenced) return status;
        if (status == Status.NoPendingBatch) revert NoPendingBatch();
        if (status == Status.BatchInvalidated) revert BatchInvalidated();
        if (status == Status.ChallengeWindowOpen) revert ChallengeWindowOpen();
        if (status == Status.StateAncestry) revert StateAncestry();
        if (status == Status.EpochOverflow) revert EpochOverflow();
        if (status == Status.CustodyArithmetic) revert CustodyArithmetic();
        revert OperatorHardFaulted();
    }

    // ---------------------------------------------------------------------------------------
    // Withdrawal claims
    // ---------------------------------------------------------------------------------------

    /// @notice Pay one payout under the finalized payout head (`claim_withdrawal`,
    /// settlement.rs:1710-1736). Available after a fault.
    /// @param predecessor Start of the claimed range immediately before or containing the claimed
    /// location, or zero when no range starts at or before it. The contract checks it against
    /// its own ordered list, so a wrong hint fails instead of hiding a covering range.
    /// @param claim The crate's `WithdrawalClaim` encoding (transition.rs:1024-1047).
    function claimWithdrawal(uint64 predecessor, bytes calldata claim)
        external
        returns (uint64 rangeStart, uint64 rangeEnd)
    {
        LogHead memory hd = finalizedPayouts;
        (uint64 index, uint64 amount, address destination, uint64 start, uint64 end) = Claims.claim(
            claimState,
            Claims.Head(hd.root, hd.operations, hd.floor),
            claimableBalance,
            predecessor,
            claim,
            maxDestinationBytes
        );
        claimableBalance -= amount;
        emit WithdrawalClaimed(index, destination, amount, start, end);
        if (amount != 0 && !ITIP20(asset).transfer(destination, amount)) revert TransferFailed();
        return (start, end);
    }

    // ---------------------------------------------------------------------------------------
    // Encoding
    // ---------------------------------------------------------------------------------------

    /// @dev `DepositBatch` decoding, in `AdmissionVerifier.decodeDeposits`.
    function _decodeDeposits(bytes calldata encoded)
        private
        pure
        returns (bytes calldata records, uint256 count, uint64 total)
    {
        (bool ok, uint256 offset, uint256 n, uint64 sum) = AdmissionVerifier.decodeDeposits(encoded);
        if (!ok) revert DepositBatchEncoding();
        return (encoded[offset:], n, sum);
    }

    /// @dev Decode a `WithdrawalBatch` and compute its vector root. Signatures are checked where
    /// upstream checks them: at intake for chain-queued requests and at registration for extras.
    /// Admission binds the same bytes through the registered root.
    function _withdrawalBoundary(bytes calldata encoded) private view returns (bytes32 root, uint256 count) {
        return Withdrawals.boundary(encoded, MAX_WITHDRAWAL_RECORDS, maxDestinationBytes);
    }

    /// @dev `RootBundle` decoding (transition.rs:285-298) with `LogHead::try_new` checks
    /// (logs.rs:178-194): `operations > 0`, `operations <= MAX_LEAVES`, `floor < operations`.
    function _decodeRoots(bytes calldata encoded) private pure returns (Roots memory r) {
        if (encoded.length != ROOT_BUNDLE_SIZE) revert RootsEncoding();
        r.change = LogHead(Codec.readBytes32(encoded, 0), Codec.readU64(encoded, 32), Codec.readU64(encoded, 40));
        r.rowCount = Codec.readU64(encoded, 48);
        r.outputs = LogHead(Codec.readBytes32(encoded, 56), Codec.readU64(encoded, 88), Codec.readU64(encoded, 96));
        r.successor = Codec.readBytes32(encoded, 104);
        r.successorOperations = Codec.readU64(encoded, 136);
        r.successorSyncBoundary = Codec.readU64(encoded, 144);
        if (!_validHead(r.change) || !_validHead(r.outputs)) revert RootsEncoding();
    }

    function _validHead(LogHead memory h) private pure returns (bool) {
        return h.operations != 0 && h.operations <= MMR_MAX_LEAVES && h.floor < h.operations;
    }

    /// @dev Epoch anchor (transition.rs:533-544).
    function _anchor(uint64 epoch, bytes32 depositRoot, bytes32 withdrawalRoot, bytes memory limits)
        private
        view
        returns (bytes32)
    {
        return sha256(
            abi.encodePacked(
                EPOCH_ANCHOR_NAMESPACE,
                deployment,
                depositRoot,
                withdrawalRoot,
                epoch,
                operator,
                limits,
                committeeCommitment
            )
        );
    }

    /// @dev `CloseLimits` encoding (transition.rs:448-459).
    function _limits(Epoch storage rec) private view returns (bytes memory) {
        uint64[8] memory l = rec.limits;
        return abi.encodePacked(l[0], l[1], l[2], l[3], l[4], l[5], l[6], l[7]);
    }

    /// @dev `CloseContext` encoding (transition.rs:870-882): `EpochContext` (transition.rs:690-699),
    /// then the predecessor state root, log heads, rows and liability, both deadlines and floors.
    function _closeContext(Epoch storage rec, uint64 epoch, bytes memory limits, Head memory hd)
        private
        view
        returns (bytes memory)
    {
        bytes memory epochContext = abi.encodePacked(
            rec.anchor, epoch, operator, deployment, rec.depositRoot, rec.withdrawalRoot, limits, committeeCommitment
        );
        return bytes.concat(
            epochContext,
            abi.encodePacked(
                hd.stateRoot,
                hd.activity.root,
                hd.activity.operations,
                hd.activity.floor,
                hd.payouts.root,
                hd.payouts.operations,
                hd.payouts.floor
            ),
            abi.encodePacked(
                hd.rowsStart,
                hd.rowsEnd,
                hd.liability,
                rec.admissionDeadline,
                rec.challengeDeadline,
                rec.floorActivity,
                rec.floorPayouts
            )
        );
    }

    function _logsHash(LogHead memory activity, LogHead memory payouts) private pure returns (bytes32) {
        return keccak256(abi.encode(activity, payouts));
    }

    /// @dev The admitted head: the pipeline back, or the finalized prefix when the pipeline is empty.
    function _head() private view returns (Head memory h) {
        if (admittedEnd == expectedEpoch) {
            h.stateRoot = currentStateRoot;
            h.activity = finalizedActivity;
            h.payouts = finalizedPayouts;
            h.rowsStart = finalizedRowsStart;
            h.rowsEnd = finalizedRowsEnd;
            h.liability = currentLiability;
        } else {
            Epoch storage back = epochs[(admittedEnd - 1) % EPOCH_RING];
            h.stateRoot = back.successorRoot;
            h.activity = LogHead(back.activityRoot, back.activityOperations, back.activityFloor);
            h.payouts = LogHead(back.payoutRoot, back.payoutOperations, back.payoutFloor);
            h.rowsStart = back.rowsStart;
            h.rowsEnd = back.rowsEnd;
            h.liability = back.successorLiability;
        }
    }

    function _compare96(bytes memory a, bytes memory b) private pure returns (int256) {
        for (uint256 i; i < 96; i += 32) {
            uint256 x;
            uint256 y;
            assembly ("memory-safe") {
                x := mload(add(add(a, 0x20), i))
                y := mload(add(add(b, 0x20), i))
            }
            if (x < y) return -1;
            if (x > y) return 1;
        }
        return 0;
    }

    function _now() private view returns (uint64) {
        return uint64(block.timestamp);
    }

    // ---------------------------------------------------------------------------------------
    // Views
    // ---------------------------------------------------------------------------------------

    /// @notice The fields of a stored epoch that callers read, if it is still in the ring. All zero
    /// when the epoch is not registered.
    function epochRecord(uint64 epoch) external view returns (EpochView memory v) {
        Epoch storage rec = epochs[epoch % EPOCH_RING];
        if (rec.epoch != epoch || rec.status == 0) return v;
        v = EpochView(
            rec.anchor,
            rec.batchId,
            rec.status,
            rec.challengeKind,
            rec.admissionDeadline,
            rec.challengeDeadline,
            rec.withdrawalTotal,
            rec.successorLiability,
            rec.floorActivity,
            rec.floorPayouts
        );
    }

    /// @notice The claimed range starting at `start`: its exclusive end (zero when absent) and the
    /// start of the next range.
    function claimed(uint64 start) external view returns (uint64 end, uint64 next) {
        Claims.Range storage r = claimState.ranges[start];
        return (r.end, r.next);
    }

    /// @notice First and last claimed range starts (zero when empty) and the number of ranges.
    function claimedRanges() external view returns (uint64 first, uint64 last, uint64 count) {
        return (claimState.head, claimState.tail, claimState.count);
    }

    /// @notice The admitted head the next frontier binds as its predecessor.
    function head() external view returns (Head memory) {
        return _head();
    }

    /// @notice The `CloseContext` encoding the frontier's header must commit to.
    function frontierContext() external view returns (bytes memory) {
        if (registeredEnd <= admittedEnd) revert NoRegisteredEpoch();
        Epoch storage rec = epochs[admittedEnd % EPOCH_RING];
        return _closeContext(rec, admittedEnd, _limits(rec), _head());
    }

    /// @notice An account's chain-queued withdrawal, if any (`deadline` zero when none).
    function pendingWithdrawal(bytes32 account) external view returns (Withdrawals.Pending memory) {
        return withdrawalState.pending[account];
    }

    /// @notice The account whose chain-queued withdrawal has the smallest `(deadline, account)`.
    function pendingWithdrawalHead() external view returns (bytes32) {
        return withdrawalState.head;
    }

    /// @notice `unfinalized_withdrawal_deadline` (settlement.rs:1061-1088), zero when none.
    function unfinalizedWithdrawalDeadline(bytes32 account) external view returns (uint64) {
        return Withdrawals.unfinalizedDeadline(withdrawalState, _window(), account);
    }

    /// @notice The deadline of `account`'s request in `epoch`'s registered batch, or zero.
    function carriedWithdrawalDeadline(uint64 epoch, bytes32 account) external view returns (uint64) {
        return withdrawalState.carried[epoch][account];
    }

    /// @notice The deadline until which a withdrawal id stays consumed.
    function withdrawalReplayExpiry(bytes32 id) external view returns (uint64) {
        return withdrawalState.replayExpiry[id];
    }

    /// @notice The inbox chain value committing every deposit before `index`, while retained.
    function inboxCommitment(uint64 index) external view returns (bytes32) {
        return inboxChain[index % INBOX_RING];
    }
}
