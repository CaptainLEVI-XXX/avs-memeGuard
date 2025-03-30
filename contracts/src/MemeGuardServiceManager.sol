// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import {ECDSAServiceManagerBase} from "@eigenlayer-middleware/src/unaudited/ECDSAServiceManagerBase.sol";
import {ECDSAStakeRegistry} from "@eigenlayer-middleware/src/unaudited/ECDSAStakeRegistry.sol";
import {IServiceManager} from "@eigenlayer-middleware/src/interfaces/IServiceManager.sol";
import {ECDSAUpgradeable} from "@openzeppelin-upgrades/contracts/utils/cryptography/ECDSAUpgradeable.sol";
import {IERC1271Upgradeable} from "@openzeppelin-upgrades/contracts/interfaces/IERC1271Upgradeable.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

/**
 * @title MemeGuardServiceManager
 * @notice EigenLayer AVS for memecoin , strategy and Transtion risk assessment
 * @dev Implements a decentralized risk assessment system compatible with EigenLayer
 */
contract MemeGuardServiceManager is ECDSAServiceManagerBase {
    using ECDSAUpgradeable for bytes32;
    using Strings for uint256;

    // ============ Structs ============
    /**
     * @notice Struct for task data
     * @param assessmentType Type of assessment (strategy, token, transition)
     * @param targetId ID of the target being assessed
     * @param targetAddress Address of the target implementation or token
     * @param taskCreatedBlock Block number when the task was created
     */
    struct Task {
        string assessmentType;  
        bytes32 targetId;
        address targetAddress;
        uint32 taskCreatedBlock;
    }

    /**
     * @notice Struct for risk assessment data
     * @param targetId ID of the target being assessed
     * @param riskScore Risk score assessment (0-100)
     * @param isCritical Whether a critical vulnerability was found
     * @param timestamp Time when the assessment was submitted
     */
    struct RiskAssessment {
        bytes32 targetId;
        uint8 riskScore;
        bool isCritical;
        uint256 timestamp;
    }

    // ============ Events ============
    /**
     * @notice Emitted when a new assessment task is created
     * @param taskId ID of the created task
     * @param task Task details
     */
    event NewTaskCreated(uint32 taskId, Task task);
    
    /**
     * @notice Emitted when an operator responds to a task
     * @param taskId ID of the task being responded to
     * @param task Task details
     * @param operator Address of the responding operator
     */
    event TaskResponded(uint32 taskId, Task task, address operator);
    
    /**
     * @notice Emitted when a risk assessment is submitted
     * @param targetId ID of the target being assessed
     * @param assessmentType Type of assessment
     * @param riskScore Risk score assessment
     * @param isCritical Whether a critical vulnerability was found
     */
    event RiskAssessmentSubmitted(
        bytes32 targetId,
        string assessmentType,
        uint8 riskScore,
        bool isCritical
    );
    
    /**
     * @notice Emitted when consensus is reached on a risk assessment
     * @param targetId ID of the target being assessed
     * @param assessmentType Type of assessment
     * @param riskScore Consensus risk score
     * @param isCritical Consensus on critical status
     */
    event RiskConsensusReached(
        bytes32 targetId,
        string assessmentType,
        uint8 riskScore,
        bool isCritical
    );

    // ============ Task Management ============
    uint32 public latestTaskNum;
    mapping(uint32 => bytes32) public allTaskHashes;
    mapping(address => mapping(uint32 => bytes)) public allTaskResponses;
    
    // ============ Risk Assessment Storage ============
    // Maps assessment type + target ID to a mapping of operator responses
    mapping(bytes32 => mapping(address => RiskAssessment)) public operatorAssessments;
    
    // Maps assessment type + target ID to consensus data
    mapping(bytes32 => RiskAssessment) public consensusAssessments;
    
    // Maps assessment type + target ID + risk score to vote count
    mapping(bytes32 => mapping(uint8 => uint256)) public riskScoreVotes;
    
    // Maps assessment type + target ID to critical risk vote count
    mapping(bytes32 => uint256) public criticalRiskVotes;
    
    // Tracks operators who have submitted assessments
    mapping(bytes32 => mapping(address => bool)) public hasSubmittedAssessment;
    
    // ============ Configuration ============
    uint256 public quorum;
    mapping(address => bool) public authorizedCallers;


    // max interval in blocks for responding to a task
    // operators can be penalized if they don't respond in time
    uint32 public immutable MAX_RESPONSE_INTERVAL_BLOCKS;
    
    // ============ Errors ============
    error InvalidTask();
    error TaskAlreadyResponded();
    error InvalidSignature();
    error TaskResponseMismatch();
    error Unauthorized();

    /**
     * @notice Constructor for MemeGuardServiceManager
     * @param _avsDirectory AVS Directory address
     * @param _stakeRegistry Stake Registry address
     * @param _rewardsCoordinator Rewards Coordinator address
     * @param _delegationManager Delegation Manager address
     * @param _allocationManager Allocation mAnager
     * @param _maxResponseIntervalBlocks  max responsive between blocks
     * param 
     */

    constructor(
        address _avsDirectory,
        address _stakeRegistry,
        address _rewardsCoordinator,
        address _delegationManager,
        address _allocationManager,
        uint32 _maxResponseIntervalBlocks
    )
        ECDSAServiceManagerBase(
            _avsDirectory,
            _stakeRegistry,
            _rewardsCoordinator,
            _delegationManager,
            _allocationManager
        )
    {

        MAX_RESPONSE_INTERVAL_BLOCKS = _maxResponseIntervalBlocks;
        quorum = 3; // Default quorum
    }
    
    /**
     * @notice Initializes the service manager
     * @param initialOwner Initial owner address
     * @param _rewardsInitiator Rewards initiator address
     */
    function initialize(address initialOwner, address _rewardsInitiator) external initializer {
        __ServiceManagerBase_init(initialOwner, _rewardsInitiator);
    }
    
    // ============ Authorization Functions ============
    
    /**
     * @notice Set authorized caller status
     * @param caller Address to authorize/deauthorize
     * @param status Authorization status
     */
    function setAuthorizedCaller(address caller, bool status) external onlyOwner {
        authorizedCallers[caller] = status;
    }
    
    /**
     * @notice Set quorum requirement
     * @param _quorum New quorum value
     */
    function setQuorum(uint256 _quorum) external onlyOwner {
        quorum = _quorum;
    }
    
    /**
     * @notice Only authorized callers or owner can call
     */
    modifier onlyAuthorized() {
        if (!authorizedCallers[msg.sender] && msg.sender != owner()) {
            revert Unauthorized();
        }
        _;
    }
    
    // ============ Task Management Functions ============
    
    /**
     * @notice Create a new assessment task
     * @param assessmentType Type of assessment ("strategy", "token", or "transition")
     * @param targetId ID of the target being assessed
     * @param targetAddress Address of the target implementation or token
     * @return task The created task
     */
    function createAssessmentTask(
        string calldata assessmentType,
        bytes32 targetId,
        address targetAddress
    ) external returns (Task memory) {
        // Create new task
        Task memory newTask;
        newTask.assessmentType = assessmentType;
        newTask.targetId = targetId;
        newTask.targetAddress = targetAddress;
        newTask.taskCreatedBlock = uint32(block.number);
        
        // Store task hash
        allTaskHashes[latestTaskNum] = keccak256(abi.encode(newTask));
        
        // Emit event
        emit NewTaskCreated(latestTaskNum, newTask);
        
        // Increment task counter
        latestTaskNum = latestTaskNum + 1;
        
        return newTask;
    }
    
    /**
     * @notice Respond to an assessment task
     * @param task The task being responded to
     * @param taskId Task ID
     * @param signature Signed assessment data
     * @param riskScore Risk score assessment (0-100)
     * @param isCritical Whether a critical vulnerability was found
     * @param reportHash IPFS hash of detailed assessment report
     */
    function respondToAssessment(
        Task calldata task,
        uint32 taskId,
        bytes memory signature,
        uint8 riskScore,
        bool isCritical,
        string memory reportHash
    ) external {
        // Verify task hash matches stored hash
        if (keccak256(abi.encode(task)) != allTaskHashes[taskId]) {
            revert InvalidTask();
        }
        
        // Verify operator hasn't already responded
        if (allTaskResponses[msg.sender][taskId].length > 0) {
            revert TaskAlreadyResponded();
        }
        
        // Create assessment ID (combines assessment type and target ID)
        bytes32 assessmentId = keccak256(abi.encodePacked(task.assessmentType, task.targetId));
        
        // Verify signature
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                task.assessmentType,
                task.targetId,
                riskScore,
                isCritical,
                reportHash
            )
        );
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        bytes4 magicValue = IERC1271Upgradeable.isValidSignature.selector;
        
        // Verify signature is valid
        if (
            !(
                magicValue == 
                ECDSAStakeRegistry(stakeRegistry).isValidSignature(
                    ethSignedMessageHash, 
                    signature
                )
            )
        ) {
            revert InvalidSignature();
        }
        
        // Store response
        allTaskResponses[msg.sender][taskId] = signature;
        
        // Store assessment
        operatorAssessments[assessmentId][msg.sender] = RiskAssessment({
            targetId: task.targetId,
            riskScore: riskScore,
            isCritical: isCritical,
            timestamp: block.timestamp
        });
        
        // Mark as submitted
        hasSubmittedAssessment[assessmentId][msg.sender] = true;
        
        // Update vote counts
        riskScoreVotes[assessmentId][riskScore]++;
        if (isCritical) {
            criticalRiskVotes[assessmentId]++;
        }
        
        // Emit event
        emit RiskAssessmentSubmitted(task.targetId, task.assessmentType, riskScore, isCritical);
        emit TaskResponded(taskId, task, msg.sender);
        
        // Check for consensus
        _checkForConsensus(assessmentId, task.assessmentType, task.targetId);
    }
    
    /**
     * @notice Check if consensus has been reached for an assessment
     * @param assessmentId Combined ID of assessment type and target
     * @param assessmentType Type of assessment
     * @param targetId ID of the target being assessed
     */
    function _checkForConsensus(
        bytes32 assessmentId,
        string memory assessmentType,
        bytes32 targetId
    ) internal {
        // Find risk score with most votes
        uint8 consensusRiskScore = 0;
        uint256 maxVotes = 0;
        
        for (uint8 i = 0; i <= 100; i++) {
            uint256 votes = riskScoreVotes[assessmentId][i];
            if (votes > maxVotes) {
                maxVotes = votes;
                consensusRiskScore = i;
            }
        }
        
        // Check if risk score has reached quorum
        if (maxVotes >= quorum) {
            // Check if critical vulnerability consensus was reached
            bool consensusIsCritical = criticalRiskVotes[assessmentId] >= quorum;
            
            // Record consensus
            consensusAssessments[assessmentId] = RiskAssessment({
                targetId: targetId,
                riskScore: consensusRiskScore,
                isCritical: consensusIsCritical,
                timestamp: block.timestamp
            });
            
            // Emit event
            emit RiskConsensusReached(targetId, assessmentType, consensusRiskScore, consensusIsCritical);
        }
    }
    
    // ============ View Functions ============
    
    /**
     * @notice Check if strategy has critical risks
     * @param strategyId Strategy ID
     * @return assessed Whether the strategy has been assessed
     * @return riskScore The overall risk score
     * @return isCritical Whether the strategy has critical risks
     */
    function checkStrategySafety(bytes32 strategyId) external view returns (
        bool assessed,
        uint8 riskScore,
        bool isCritical
    ) {
        bytes32 assessmentId = keccak256(abi.encodePacked("strategy", strategyId));
        RiskAssessment memory assessment = consensusAssessments[assessmentId];
        
        assessed = (assessment.timestamp > 0);
        riskScore = assessment.riskScore;
        isCritical = assessment.isCritical;
        
        return (assessed, riskScore, isCritical);
    }
    
    /**
     * @notice Check if token has suspicious activity
     * @param poolId Pool ID
     * @return assessed Whether the token has been assessed
     * @return riskScore The overall risk score
     * @return isSuspicious Whether the token is suspicious
     */
    function checkTokenSafety(bytes32 poolId) external view returns (
        bool assessed,
        uint8 riskScore,
        bool isSuspicious
    ) {
        bytes32 assessmentId = keccak256(abi.encodePacked("token", poolId));
        RiskAssessment memory assessment = consensusAssessments[assessmentId];
        
        assessed = (assessment.timestamp > 0);
        riskScore = assessment.riskScore;
        isSuspicious = assessment.isCritical; // Suspicious = critical
        
        return (assessed, riskScore, isSuspicious);
    }
    
    /**
     * @notice Check if a pool is ready for transition
     * @param poolId Pool ID
     * @return assessed Whether the transition has been assessed
     * @return riskScore The overall risk score
     * @return isReady Whether the pool is ready for transition
     */
    function checkTransitionReadiness(bytes32 poolId) external view returns (
        bool assessed,
        uint8 riskScore,
        bool isReady
    ) {
        bytes32 assessmentId = keccak256(abi.encodePacked("transition", poolId));
        RiskAssessment memory assessment = consensusAssessments[assessmentId];
        
        assessed = (assessment.timestamp > 0);
        riskScore = assessment.riskScore;
        
        // A pool is ready for transition if it has no critical issues and risk score below threshold
        isReady = assessed && !assessment.isCritical && assessment.riskScore <= 50;
        
        return (assessed, riskScore, isReady);
    }

    // Required EigenLayer interface functions
    function addPendingAdmin(address admin) external onlyOwner {}
    function removePendingAdmin(address pendingAdmin) external onlyOwner {}
    function removeAdmin(address admin) external onlyOwner {}
    function setAppointee(address appointee, address target, bytes4 selector) external onlyOwner {}
    function removeAppointee(address appointee, address target, bytes4 selector) external onlyOwner {}
    function deregisterOperatorFromOperatorSets(address operator, uint32[] memory operatorSetIds) external {}
}