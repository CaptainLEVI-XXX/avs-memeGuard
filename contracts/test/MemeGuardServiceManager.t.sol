// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import {MemeGuardServiceManager} from "../src/MemeGuardServiceManager.sol";
import {MockAVSDeployer} from "@eigenlayer-middleware/test/utils/MockAVSDeployer.sol";
import {ECDSAStakeRegistry} from "@eigenlayer-middleware/src/unaudited/ECDSAStakeRegistry.sol";
import {Vm} from "forge-std/Vm.sol";
import {console2} from "forge-std/Test.sol";
import {HelloWorldDeploymentLib} from "../script/utils/HelloWorldDeploymentLib.sol";
import {
    CoreDeployLib, CoreDeploymentParsingLib
} from "../script/utils/CoreDeploymentParsingLib.sol";
import {UpgradeableProxyLib} from "../script/utils/UpgradeableProxyLib.sol";
import {ERC20Mock} from "./ERC20Mock.sol";
import {IERC20, StrategyFactory} from "@eigenlayer/contracts/strategies/StrategyFactory.sol";

import {
    IECDSAStakeRegistryTypes,
    IStrategy
} from "@eigenlayer-middleware/src/interfaces/IECDSAStakeRegistry.sol";
import {IStrategyManager} from "@eigenlayer/contracts/interfaces/IStrategyManager.sol";
import {
    IDelegationManager,
    IDelegationManagerTypes
} from "@eigenlayer/contracts/interfaces/IDelegationManager.sol";
import {DelegationManager} from "@eigenlayer/contracts/core/DelegationManager.sol";
import {StrategyManager} from "@eigenlayer/contracts/core/StrategyManager.sol";
import {ISignatureUtilsMixinTypes} from "@eigenlayer/contracts/interfaces/ISignatureUtilsMixin.sol";
import {AVSDirectory} from "@eigenlayer/contracts/core/AVSDirectory.sol";
import {IAVSDirectoryTypes} from "@eigenlayer/contracts/interfaces/IAVSDirectory.sol";
import {Test, console2 as console} from "forge-std/Test.sol";
import {IMemeGuardServiceManager} from "../src/IMemeGuardServiceManager.sol";
import {ECDSAUpgradeable} from
    "@openzeppelin-upgrades/contracts/utils/cryptography/ECDSAUpgradeable.sol";

contract MemeGuardServiceManagerSetup is Test {
    // used for `toEthSignedMessageHash`
    using ECDSAUpgradeable for bytes32;

    IECDSAStakeRegistryTypes.Quorum internal quorum;

    struct Operator {
        Vm.Wallet key;
        Vm.Wallet signingKey;
    }

    struct PlatformUser {
        Vm.Wallet key;
    }

    struct AVSOwner {
        Vm.Wallet key;
    }

    Operator[] internal operators;
    PlatformUser internal platform;
    AVSOwner internal owner;

    HelloWorldDeploymentLib.DeploymentData internal memeGuardDeployment;
    CoreDeployLib.DeploymentData internal coreDeployment;
    CoreDeployLib.DeploymentConfigData coreConfigData;

    address proxyAdmin;

    ERC20Mock public mockToken;

    mapping(address => IStrategy) public tokenToStrategy;

    function setUp() public virtual {
        platform = PlatformUser({key: vm.createWallet("platform_wallet")});
        owner = AVSOwner({key: vm.createWallet("owner_wallet")});

        proxyAdmin = UpgradeableProxyLib.deployProxyAdmin();

        coreConfigData =
            CoreDeploymentParsingLib.readDeploymentConfigValues("test/mockData/config/core/", 1337);
        coreDeployment = CoreDeployLib.deployContracts(proxyAdmin, coreConfigData);

        vm.prank(coreConfigData.strategyManager.initialOwner);
        StrategyManager(coreDeployment.strategyManager).setStrategyWhitelister(
            coreDeployment.strategyFactory
        );

        mockToken = new ERC20Mock();

        IStrategy strategy = addStrategy(address(mockToken));
        quorum.strategies.push(
            IECDSAStakeRegistryTypes.StrategyParams({strategy: strategy, multiplier: 10_000})
        );

        memeGuardDeployment = HelloWorldDeploymentLib.deployContracts(
            proxyAdmin, coreDeployment, quorum, owner.key.addr, owner.key.addr
        );
        memeGuardDeployment.strategy = address(strategy);
        memeGuardDeployment.token = address(mockToken);
        labelContracts(coreDeployment, memeGuardDeployment);
    }

    function addStrategy(
        address token
    ) public returns (IStrategy) {
        if (tokenToStrategy[token] != IStrategy(address(0))) {
            return tokenToStrategy[token];
        }

        StrategyFactory strategyFactory = StrategyFactory(coreDeployment.strategyFactory);
        IStrategy newStrategy = strategyFactory.deployNewStrategy(IERC20(token));
        tokenToStrategy[token] = newStrategy;
        return newStrategy;
    }

    function labelContracts(
        CoreDeployLib.DeploymentData memory _coreDeployment,
        HelloWorldDeploymentLib.DeploymentData memory _memeGuardDeployment
    ) internal {
        vm.label(_coreDeployment.delegationManager, "DelegationManager");
        vm.label(_coreDeployment.avsDirectory, "AVSDirectory");
        vm.label(_coreDeployment.strategyManager, "StrategyManager");
        vm.label(_coreDeployment.eigenPodManager, "EigenPodManager");
        vm.label(_coreDeployment.rewardsCoordinator, "RewardsCoordinator");
        vm.label(_coreDeployment.eigenPodBeacon, "EigenPodBeacon");
        vm.label(_coreDeployment.pauserRegistry, "PauserRegistry");
        vm.label(_coreDeployment.strategyFactory, "StrategyFactory");
        vm.label(_coreDeployment.strategyBeacon, "StrategyBeacon");
        vm.label(_memeGuardDeployment.memeGuardServiceManager, "MemeGuardServiceManager");
        vm.label(_memeGuardDeployment.stakeRegistry, "StakeRegistry");
    }

    function signWithOperatorKey(
        Operator memory operator,
        bytes32 digest
    ) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(operator.key.privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function signWithSigningKey(
        Operator memory operator,
        bytes32 digest
    ) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(operator.signingKey.privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function mintMockTokens(Operator memory operator, uint256 amount) internal {
        mockToken.mint(operator.key.addr, amount);
    }

    function depositTokenIntoStrategy(
        Operator memory operator,
        address token,
        uint256 amount
    ) internal returns (uint256) {
        IStrategy strategy = IStrategy(tokenToStrategy[token]);
        require(address(strategy) != address(0), "Strategy was not found");
        IStrategyManager strategyManager = IStrategyManager(coreDeployment.strategyManager);

        vm.startPrank(operator.key.addr);
        mockToken.approve(address(strategyManager), amount);
        uint256 shares = strategyManager.depositIntoStrategy(strategy, IERC20(token), amount);
        vm.stopPrank();

        return shares;
    }

    function registerAsOperator(
        Operator memory operator
    ) internal {
        IDelegationManager delegationManager = IDelegationManager(coreDeployment.delegationManager);

        // IDelegationManagerTypes.OperatorDetails memory operatorDetails = IDelegationManagerTypes
        //     .OperatorDetails({
        //     earningsReceiver: operator.key.addr,
        //     delegationApprover: address(0),
        //     stakerOptOutWindowBlocks: 0
        // });

        vm.prank(operator.key.addr);
        delegationManager.registerAsOperator(address(0),0, "");
    }

    function registerOperatorToAVS(
        Operator memory operator
    ) internal {
        ECDSAStakeRegistry stakeRegistry = ECDSAStakeRegistry(memeGuardDeployment.stakeRegistry);
        AVSDirectory avsDirectory = AVSDirectory(coreDeployment.avsDirectory);

        bytes32 salt = keccak256(abi.encodePacked(block.timestamp, operator.key.addr));
        uint256 expiry = block.timestamp + 1 hours;

        bytes32 operatorRegistrationDigestHash = avsDirectory
            .calculateOperatorAVSRegistrationDigestHash(
            operator.key.addr, address(memeGuardDeployment.memeGuardServiceManager), salt, expiry
        );

        bytes memory signature = signWithOperatorKey(operator, operatorRegistrationDigestHash);

        ISignatureUtilsMixinTypes.SignatureWithSaltAndExpiry memory operatorSignature =
        ISignatureUtilsMixinTypes.SignatureWithSaltAndExpiry({
            signature: signature,
            salt: salt,
            expiry: expiry
        });

        vm.prank(address(operator.key.addr));
        stakeRegistry.registerOperatorWithSignature(operatorSignature, operator.signingKey.addr);
    }

    function deregisterOperatorFromAVS(
        Operator memory operator
    ) internal {
        ECDSAStakeRegistry stakeRegistry = ECDSAStakeRegistry(memeGuardDeployment.stakeRegistry);

        vm.prank(operator.key.addr);
        stakeRegistry.deregisterOperator();
    }

    function createAndAddOperator() internal returns (Operator memory) {
        Vm.Wallet memory operatorKey =
            vm.createWallet(string.concat("operator", vm.toString(operators.length)));
        Vm.Wallet memory signingKey =
            vm.createWallet(string.concat("signing", vm.toString(operators.length)));

        Operator memory newOperator = Operator({key: operatorKey, signingKey: signingKey});

        operators.push(newOperator);
        return newOperator;
    }

    function updateOperatorWeights(
        Operator[] memory _operators
    ) internal {
        ECDSAStakeRegistry stakeRegistry = ECDSAStakeRegistry(memeGuardDeployment.stakeRegistry);

        address[] memory operatorAddresses = new address[](_operators.length);
        for (uint256 i = 0; i < _operators.length; i++) {
            operatorAddresses[i] = _operators[i].key.addr;
        }

        stakeRegistry.updateOperators(operatorAddresses);
    }

    function getOperators(
        uint256 numOperators
    ) internal view returns (Operator[] memory) {
        require(numOperators <= operators.length, "Not enough operators");

        Operator[] memory operatorsMem = new Operator[](numOperators);
        for (uint256 i = 0; i < numOperators; i++) {
            operatorsMem[i] = operators[i];
        }
        // Sort the operators by address
        for (uint256 i = 0; i < numOperators - 1; i++) {
            uint256 minIndex = i;
            // Find the minimum operator by address
            for (uint256 j = i + 1; j < numOperators; j++) {
                if (operatorsMem[minIndex].key.addr > operatorsMem[j].key.addr) {
                    minIndex = j;
                }
            }
            // Swap the minimum operator with the ith operator
            Operator memory temp = operatorsMem[i];
            operatorsMem[i] = operatorsMem[minIndex];
            operatorsMem[minIndex] = temp;
        }
        return operatorsMem;
    }

    function createAssessmentTask(
        string memory assessmentType,
        bytes32 targetId,
        address targetAddress
    ) internal returns (MemeGuardServiceManager.Task memory) {
        IMemeGuardServiceManager serviceManager =
            IMemeGuardServiceManager(memeGuardDeployment.memeGuardServiceManager);

        vm.prank(platform.key.addr);
        return serviceManager.createAssessmentTask(assessmentType, targetId, targetAddress);
    }

    function respondToAssessment(
        Operator memory operator,
        MemeGuardServiceManager.Task memory task,
        uint32 taskId,
        uint8 riskScore,
        bool isCritical,
        string memory reportHash
    ) internal {
        // Create message hash
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
        
        // Sign the message
        bytes memory signature = signWithSigningKey(operator, ethSignedMessageHash);
        
        // Submit assessment
        IMemeGuardServiceManager serviceManager = 
            IMemeGuardServiceManager(memeGuardDeployment.memeGuardServiceManager);
            
        vm.prank(operator.key.addr);
        serviceManager.respondToAssessment(
            task,
            taskId,
            signature,
            riskScore,
            isCritical,
            reportHash
        );
    }
}

contract MemeGuardServiceManagerInitialization is MemeGuardServiceManagerSetup {
    function testInitialization() public view {
        ECDSAStakeRegistry stakeRegistry = ECDSAStakeRegistry(memeGuardDeployment.stakeRegistry);

        IECDSAStakeRegistryTypes.Quorum memory quorum = stakeRegistry.quorum();

        assertGt(quorum.strategies.length, 0, "No strategies in quorum");
        assertEq(
            address(quorum.strategies[0].strategy),
            address(tokenToStrategy[address(mockToken)]),
            "First strategy doesn't match mock token strategy"
        );

        assertTrue(memeGuardDeployment.stakeRegistry != address(0), "StakeRegistry not deployed");
        assertTrue(
            memeGuardDeployment.memeGuardServiceManager != address(0),
            "MemeGuardServiceManager not deployed"
        );
        assertTrue(coreDeployment.delegationManager != address(0), "DelegationManager not deployed");
        assertTrue(coreDeployment.avsDirectory != address(0), "AVSDirectory not deployed");
        assertTrue(coreDeployment.strategyManager != address(0), "StrategyManager not deployed");
        assertTrue(coreDeployment.eigenPodManager != address(0), "EigenPodManager not deployed");
        assertTrue(coreDeployment.strategyFactory != address(0), "StrategyFactory not deployed");
        assertTrue(coreDeployment.strategyBeacon != address(0), "StrategyBeacon not deployed");
    }
}

contract RegisterOperator is MemeGuardServiceManagerSetup {
    uint256 internal constant INITIAL_BALANCE = 100 ether;
    uint256 internal constant DEPOSIT_AMOUNT = 1 ether;
    uint256 internal constant OPERATOR_COUNT = 4;

    DelegationManager internal delegationManager;
    AVSDirectory internal avsDirectory;
    IMemeGuardServiceManager internal sm;
    ECDSAStakeRegistry internal stakeRegistry;

    function setUp() public virtual override {
        super.setUp();
        /// Setting to internal state for convenience
        delegationManager = DelegationManager(coreDeployment.delegationManager);
        avsDirectory = AVSDirectory(coreDeployment.avsDirectory);
        sm = IMemeGuardServiceManager(memeGuardDeployment.memeGuardServiceManager);
        stakeRegistry = ECDSAStakeRegistry(memeGuardDeployment.stakeRegistry);

        addStrategy(address(mockToken));

        while (operators.length < OPERATOR_COUNT) {
            createAndAddOperator();
        }

        for (uint256 i = 0; i < OPERATOR_COUNT; i++) {
            mintMockTokens(operators[i], INITIAL_BALANCE);

            depositTokenIntoStrategy(operators[i], address(mockToken), DEPOSIT_AMOUNT);

            registerAsOperator(operators[i]);
        }
    }

    function testVerifyOperatorStates() public view {
        for (uint256 i = 0; i < OPERATOR_COUNT; i++) {
            address operatorAddr = operators[i].key.addr;

            uint256 operatorShares =
                delegationManager.operatorShares(operatorAddr, tokenToStrategy[address(mockToken)]);
            assertEq(
                operatorShares, DEPOSIT_AMOUNT, "Operator shares in DelegationManager incorrect"
            );
        }
    }

    function test_RegisterOperatorToAVS() public {
        address operatorAddr = operators[0].key.addr;
        registerOperatorToAVS(operators[0]);
        assertTrue(
            avsDirectory.avsOperatorStatus(address(sm), operatorAddr)
                == IAVSDirectoryTypes.OperatorAVSRegistrationStatus.REGISTERED,
            "Operator not registered in AVSDirectory"
        );

        address signingKey = stakeRegistry.getLatestOperatorSigningKey(operatorAddr);
        assertTrue(signingKey != address(0), "Operator signing key not set in ECDSAStakeRegistry");

        uint256 operatorWeight = stakeRegistry.getLastCheckpointOperatorWeight(operatorAddr);
        assertTrue(operatorWeight > 0, "Operator weight not set in ECDSAStakeRegistry");
    }
}

contract CreateTask is MemeGuardServiceManagerSetup {
    IMemeGuardServiceManager internal sm;
    bytes32 constant TEST_STRATEGY_ID = bytes32(uint256(1));
    address constant TEST_IMPLEMENTATION = address(0x123);

    function setUp() public override {
        super.setUp();
        sm = IMemeGuardServiceManager(memeGuardDeployment.memeGuardServiceManager);
        
        // Authorize the platform
        vm.prank(owner.key.addr);
        sm.setAuthorizedCaller(platform.key.addr, true);
    }

    function testCreateTask() public {
        vm.prank(platform.key.addr);
        MemeGuardServiceManager.Task memory newTask = sm.createAssessmentTask(
            "strategy",
            TEST_STRATEGY_ID,
            TEST_IMPLEMENTATION
        );
        
        assertEq(newTask.assessmentType, "strategy", "Task type incorrect");
        assertEq(newTask.targetId, TEST_STRATEGY_ID, "Target ID incorrect");
        assertEq(newTask.targetAddress, TEST_IMPLEMENTATION, "Target address incorrect");
        assertEq(newTask.taskCreatedBlock, uint32(block.number), "Task created block incorrect");
    }
}

contract RespondToAssessment is MemeGuardServiceManagerSetup {
    using ECDSAUpgradeable for bytes32;

    uint256 internal constant INITIAL_BALANCE = 100 ether;
    uint256 internal constant DEPOSIT_AMOUNT = 1 ether;
    uint256 internal constant OPERATOR_COUNT = 4;

    IDelegationManager internal delegationManager;
    AVSDirectory internal avsDirectory;
    IMemeGuardServiceManager internal sm;
    ECDSAStakeRegistry internal stakeRegistry;
    
    bytes32 constant TEST_STRATEGY_ID = bytes32(uint256(1));
    bytes32 constant TEST_POOL_ID = bytes32(uint256(2));
    address constant TEST_IMPLEMENTATION = address(0x123);
    address constant TEST_TOKEN_ADDRESS = address(0x456);

    function setUp() public override {
        super.setUp();

        delegationManager = IDelegationManager(coreDeployment.delegationManager);
        avsDirectory = AVSDirectory(coreDeployment.avsDirectory);
        sm = IMemeGuardServiceManager(memeGuardDeployment.memeGuardServiceManager);
        stakeRegistry = ECDSAStakeRegistry(memeGuardDeployment.stakeRegistry);

        // Authorize platform
        vm.prank(owner.key.addr);
        sm.setAuthorizedCaller(platform.key.addr, true);
        
        // Set quorum to 2
        vm.prank(owner.key.addr);
        sm.setQuorum(2);

        addStrategy(address(mockToken));

        while (operators.length < OPERATOR_COUNT) {
            createAndAddOperator();
        }

        for (uint256 i = 0; i < OPERATOR_COUNT; i++) {
            mintMockTokens(operators[i], INITIAL_BALANCE);

            depositTokenIntoStrategy(operators[i], address(mockToken), DEPOSIT_AMOUNT);

            registerAsOperator(operators[i]);

            registerOperatorToAVS(operators[i]);
        }
    }

    function testRespondToAssessment() public {
        // Create a task
        MemeGuardServiceManager.Task memory task = createAssessmentTask(
            "strategy",
            TEST_STRATEGY_ID,
            TEST_IMPLEMENTATION
        );
        uint32 taskId = sm.latestTaskNum() - 1;
        
        // Respond to assessment
        uint8 riskScore = 42;
        bool isCritical = false;
        string memory reportHash = "QmReportHash";
        
        // Create message hash
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
        
        // Mock signature verification
        bytes4 magicValue = bytes4(keccak256("isValidSignature(bytes32,bytes)"));
        vm.mockCall(
            address(stakeRegistry),
            abi.encodeWithSelector(
                ECDSAStakeRegistry.isValidSignature.selector,
                ethSignedMessageHash,
                bytes("mock_signature")
            ),
            abi.encode(magicValue)
        );
        
        // Respond
        vm.prank(operators[0].key.addr);
        sm.respondToAssessment(
            task,
            taskId,
            bytes("mock_signature"),
            riskScore,
            isCritical,
            reportHash
        );
        
        // Check if response was recorded
        bytes32 assessmentId = keccak256(abi.encodePacked(task.assessmentType, task.targetId));
        assertTrue(sm.hasSubmittedAssessment(assessmentId, operators[0].key.addr), "Assessment not recorded");
    }
    
    function testConsensusReached() public {
        // Create a task
        MemeGuardServiceManager.Task memory task = createAssessmentTask(
            "strategy",
            TEST_STRATEGY_ID,
            TEST_IMPLEMENTATION
        );
        uint32 taskId = sm.latestTaskNum() - 1;
        
        // Assessment details
        uint8 riskScore = 42;
        bool isCritical = false;
        string memory reportHash = "QmReportHash";
        
        // Message hash
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
        
        // Mock signature verification for both operators
        bytes4 magicValue = bytes4(keccak256("isValidSignature(bytes32,bytes)"));
        vm.mockCall(
            address(stakeRegistry),
            abi.encodeWithSelector(
                ECDSAStakeRegistry.isValidSignature.selector,
                ethSignedMessageHash,
                bytes("mock_signature")
            ),
            abi.encode(magicValue)
        );
        
        // First operator submits
        vm.prank(operators[0].key.addr);
        sm.respondToAssessment(
            task,
            taskId,
            bytes("mock_signature"),
            riskScore,
            isCritical,
            reportHash
        );
        
        // Second operator submits to reach consensus
        vm.prank(operators[1].key.addr);
        sm.respondToAssessment(
            task,
            taskId,
            bytes("mock_signature"),
            riskScore,
            isCritical,
            reportHash
        );
        
        // Verify consensus was reached
        bytes32 assessmentId = keccak256(abi.encodePacked(task.assessmentType, task.targetId));
        MemeGuardServiceManager.RiskAssessment memory params = 
            sm.consensusAssessments(assessmentId);
            
        assertEq(params.targetId, task.targetId, "Target ID mismatch");
        assertEq(params.riskScore, riskScore, "Risk score mismatch");
        assertEq(params.isCritical, isCritical, "Critical flag mismatch");
    }
    
    function testCheckStrategySafety() public {
        // Create and assess a strategy
        MemeGuardServiceManager.Task memory task = createAssessmentTask(
            "strategy",
            TEST_STRATEGY_ID,
            TEST_IMPLEMENTATION
        );
        uint32 taskId = sm.latestTaskNum() - 1;
        
        // Submit from two operators for consensus
        uint8 riskScore = 42;
        bool isCritical = false;
        string memory reportHash = "QmReportHash";
        
        // Message hash
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
        
        // Mock signature verification
        bytes4 magicValue = bytes4(keccak256("isValidSignature(bytes32,bytes)"));
        vm.mockCall(
            address(stakeRegistry),
            abi.encodeWithSelector(
                ECDSAStakeRegistry.isValidSignature.selector,
                ethSignedMessageHash,
                bytes("mock_signature")
            ),
            abi.encode(magicValue)
        );
        
        // First operator submits
        vm.prank(operators[0].key.addr);
        sm.respondToAssessment(
            task,
            taskId,
            bytes("mock_signature"),
            riskScore,
            isCritical,
            reportHash
        );
        
        // Second operator submits
        vm.prank(operators[1].key.addr);
        sm.respondToAssessment(
            task,
            taskId,
            bytes("mock_signature"),
            riskScore,
            isCritical,
            reportHash
        );
        
        // Check strategy safety
        (bool assessed, uint8 resultRiskScore, bool resultIsCritical) = sm.checkStrategySafety(TEST_STRATEGY_ID);
        
        assertTrue(assessed, "Strategy not assessed");
        assertEq(resultRiskScore, riskScore, "Risk score incorrect");
        assertEq(resultIsCritical, isCritical, "Critical flag incorrect");
    }
    
    function testTokenSafetyCheck() public {
        // Create and assess a token
        MemeGuardServiceManager.Task memory task = createAssessmentTask(
            "token",
            TEST_POOL_ID,
            TEST_TOKEN_ADDRESS
        );
        uint32 taskId = sm.latestTaskNum() - 1;
        
        // Submit from two operators for consensus
        uint8 riskScore = 65;
        bool isCritical = true;  // Token is suspicious
        string memory reportHash = "QmTokenReport";
        
        // Message hash
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
        
        // Mock signature verification
        bytes4 magicValue = bytes4(keccak256("isValidSignature(bytes32,bytes)"));
        vm.mockCall(
            address(stakeRegistry),
            abi.encodeWithSelector(
                ECDSAStakeRegistry.isValidSignature.selector,
                ethSignedMessageHash,
                bytes("mock_signature")
            ),
            abi.encode(magicValue)
        );
        
        // First operator submits
        vm.prank(operators[0].key.addr);
        sm.respondToAssessment(
            task,
            taskId,
            bytes("mock_signature"),
            riskScore,
            isCritical,
            reportHash
        );
        
        // Second operator submits
        vm.prank(operators[1].key.addr);
        sm.respondToAssessment(
            task,
            taskId,
            bytes("mock_signature"),
            riskScore,
            isCritical,
            reportHash
        );
        
        // Check token safety
        (bool assessed, uint8 resultRiskScore, bool isSuspicious) = sm.checkTokenSafety(TEST_POOL_ID);
        
        assertTrue(assessed, "Token not assessed");
        assertEq(resultRiskScore, riskScore, "Risk score incorrect");
        assertTrue(isSuspicious, "Token should be marked as suspicious");
    }
    
    function testTransitionReadiness() public {
        // Create and assess a transition
        MemeGuardServiceManager.Task memory task = createAssessmentTask(
            "transition",
            TEST_POOL_ID,
            TEST_IMPLEMENTATION
        );
        uint32 taskId = sm.latestTaskNum() - 1;
        
        // Submit from two operators for consensus
        uint8 riskScore = 25;  // Low risk
        bool isCritical = false;
        string memory reportHash = "QmTransitionReport";
        
        // Message hash
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
        
        // Mock signature verification
        bytes4 magicValue = bytes4(keccak256("isValidSignature(bytes32,bytes)"));
        vm.mockCall(
            address(stakeRegistry),
            abi.encodeWithSelector(
                ECDSAStakeRegistry.isValidSignature.selector,
                ethSignedMessageHash,
                bytes("mock_signature")
            ),
            abi.encode(magicValue)
        );
        
        // First operator submits
        vm.prank(operators[0].key.addr);
        sm.respondToAssessment(
            task,
            taskId,
            bytes("mock_signature"),
            riskScore,
            isCritical,
            reportHash
        );
        
        // Second operator submits
        vm.prank(operators[1].key.addr);
        sm.respondToAssessment(
            task,
            taskId,
            bytes("mock_signature"),
            riskScore,
            isCritical,
            reportHash
        );
        
        // Check transition readiness
        (bool assessed, uint8 resultRiskScore, bool isReady) = sm.checkTransitionReadiness(TEST_POOL_ID);
        
        assertTrue(assessed, "Transition not assessed");
        assertEq(resultRiskScore, riskScore, "Risk score incorrect");
        assertTrue(isReady, "Transition should be marked as ready");
    }
}