// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import {MemeGuardServiceManager} from "./MemeGuardServiceManager.sol";

/**
 * @title IMemeGuardServiceManager
 * @notice Interface for the MemeGuard service
 */
interface IMemeGuardServiceManager {
    // State variables
    function latestTaskNum() external view returns (uint32);
    function allTaskHashes(uint32 taskId) external view returns (bytes32);
    function allTaskResponses(address operator, uint32 taskId) external view returns (bytes memory);
    function operatorAssessments(bytes32 assessmentId, address operator)
        external
        view
        returns (MemeGuardServiceManager.RiskAssessment memory);
    function consensusAssessments(bytes32 assessmentId)
        external
        view
        returns (MemeGuardServiceManager.RiskAssessment memory);
    function riskScoreVotes(bytes32 assessmentId, uint8 riskScore) external view returns (uint256);
    function criticalRiskVotes(bytes32 assessmentId) external view returns (uint256);
    function hasSubmittedAssessment(bytes32 assessmentId, address operator) external view returns (bool);
    function quorum() external view returns (uint256);
    function authorizedCallers(address caller) external view returns (bool);

    // Functions
    function createAssessmentTask(string calldata assessmentType, bytes32 targetId, address targetAddress)
        external
        returns (MemeGuardServiceManager.Task memory);

    function respondToAssessment(
        MemeGuardServiceManager.Task calldata task,
        uint32 taskId,
        bytes memory signature,
        uint8 riskScore,
        bool isCritical,
        string memory reportHash
    ) external;

    function setAuthorizedCaller(address caller, bool status) external;
    function setQuorum(uint256 _quorum) external;

    // View functions
    function checkStrategySafety(bytes32 strategyId)
        external
        view
        returns (bool assessed, uint8 riskScore, bool isCritical);

    function checkTokenSafety(bytes32 poolId)
        external
        view
        returns (bool assessed, uint8 riskScore, bool isSuspicious);

    function checkTransitionReadiness(bytes32 poolId)
        external
        view
        returns (bool assessed, uint8 riskScore, bool isReady);

    // EigenLayer required interface functions
    function addPendingAdmin(address admin) external;
    function removePendingAdmin(address pendingAdmin) external;
    function removeAdmin(address admin) external;
    function setAppointee(address appointee, address target, bytes4 selector) external;
    function removeAppointee(address appointee, address target, bytes4 selector) external;
    function deregisterOperatorFromOperatorSets(address operator, uint32[] memory operatorSetIds) external;
}
