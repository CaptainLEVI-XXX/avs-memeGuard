import { ethers } from "ethers";
import * as dotenv from "dotenv";
const fs = require('fs');
const path = require('path');
dotenv.config();

// Check if the process.env object is empty
if (!Object.keys(process.env).length) {
    throw new Error("process.env object is empty");
}

// Define the Task interface to match contract structure
interface Task {
    assessmentType: string;
    targetId: string;
    targetAddress: string;
    taskCreatedBlock: number;
}

// Setup env variables
const provider = new ethers.JsonRpcProvider(process.env.RPC_URL);
const wallet = new ethers.Wallet(process.env.PRIVATE_KEY!, provider);
/// TODO: Hack
let chainId = 31337;

const avsDeploymentData = JSON.parse(fs.readFileSync(path.resolve(__dirname, `../contracts/deployments/hello-world/${chainId}.json`), 'utf8'));
// Load core deployment data
const coreDeploymentData = JSON.parse(fs.readFileSync(path.resolve(__dirname, `../contracts/deployments/core/${chainId}.json`), 'utf8'));


const delegationManagerAddress = coreDeploymentData.addresses.delegationManager; 
const avsDirectoryAddress = coreDeploymentData.addresses.avsDirectory;
const memeGuardServiceManagerAddress = avsDeploymentData.addresses.memeGuardServiceManager;
const ecdsaStakeRegistryAddress = avsDeploymentData.addresses.stakeRegistry;


// Load ABIs
const delegationManagerABI = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../abis/IDelegationManager.json'), 'utf8'));
const ecdsaRegistryABI = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../abis/ECDSAStakeRegistry.json'), 'utf8'));
const memeGuardServiceManagerABI = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../abis/MemeGuardServiceManager.json'), 'utf8'));
const avsDirectoryABI = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../abis/IAVSDirectory.json'), 'utf8'));

// Initialize contract objects from ABIs
const delegationManager = new ethers.Contract(delegationManagerAddress, delegationManagerABI, wallet);
const memeGuardServiceManager = new ethers.Contract(memeGuardServiceManagerAddress, memeGuardServiceManagerABI, wallet);
const ecdsaRegistryContract = new ethers.Contract(ecdsaStakeRegistryAddress, ecdsaRegistryABI, wallet);
const avsDirectory = new ethers.Contract(avsDirectoryAddress, avsDirectoryABI, wallet);


const signAndRespondToTask = async (taskId: number, task: Task): Promise<void> => {
    // For MemeGuard, we generate a risk assessment with a score, critical flag, and report hash
    const riskScore = Math.floor(Math.random() * 100); // 0-99 risk score
    const isCritical = Math.random() < 0.1; // 10% chance of critical
    const reportHash = `QmReport${Math.floor(Math.random() * 10000)}`;
    
    console.log(`Processing task ${taskId}: ${task.assessmentType} for ${task.targetId}`);
    console.log(`Generated assessment: Score ${riskScore}, Critical: ${isCritical}, Report: ${reportHash}`);

    // Create message hash from assessment data
    const messageHash = ethers.solidityPackedKeccak256(
        ["string", "bytes32", "uint8", "bool", "string"],
        [task.assessmentType, task.targetId, riskScore, isCritical, reportHash]
    );
    const messageBytes = ethers.getBytes(messageHash);
    const signature = await wallet.signMessage(messageBytes);

    console.log(`Responding to task ${taskId}`);

    // Respond to the task with our assessment
    const tx = await memeGuardServiceManager.respondToAssessment(
        task,
        taskId,
        signature,
        riskScore,
        isCritical,
        reportHash
    );
    await tx.wait();
    console.log(`Successfully responded to task ${taskId}`);
};

const registerOperator = async (): Promise<void> => {
    // Registers as an Operator in EigenLayer.
    try {
        const tx1 = await delegationManager.registerAsOperator(
            "0x0000000000000000000000000000000000000000", // initDelegationApprover
            0, // allocationDelay
            "", // metadataURI
        );
        await tx1.wait();
        console.log("Operator registered to Core EigenLayer contracts");
    } catch (error) {
        console.error("Error in registering as operator:", error);
    }

    const salt = ethers.hexlify(ethers.randomBytes(32));
    const expiry = Math.floor(Date.now() / 1000) + 3600; // Example expiry, 1 hour from now

    // Define the output structure
    let operatorSignatureWithSaltAndExpiry = {
        signature: "",
        salt: salt,
        expiry: expiry
    };

    // Calculate the digest hash
    const operatorDigestHash = await avsDirectory.calculateOperatorAVSRegistrationDigestHash(
        wallet.address,
        await memeGuardServiceManager.getAddress(),
        salt,
        expiry
    );
    console.log(operatorDigestHash);

    // Sign the digest hash with the operator's private key
    console.log("Signing digest hash with operator's private key");
    const operatorSigningKey = new ethers.SigningKey(process.env.PRIVATE_KEY!);
    const operatorSignedDigestHash = operatorSigningKey.sign(operatorDigestHash);

    // Encode the signature in the required format
    operatorSignatureWithSaltAndExpiry.signature = ethers.Signature.from(operatorSignedDigestHash).serialized;

    console.log("Registering Operator to AVS Registry contract");

    // Register Operator to AVS
    const tx2 = await ecdsaRegistryContract.registerOperatorWithSignature(
        operatorSignatureWithSaltAndExpiry,
        wallet.address
    );
    await tx2.wait();
    console.log("Operator registered on AVS successfully");
};

const monitorNewTasks = async (): Promise<void> => {
    memeGuardServiceManager.on("NewTaskCreated", async (taskIndex: number, task: Task) => {
        console.log(`New task detected: ${task.assessmentType} assessment for target ${task.targetId}`);
        await signAndRespondToTask(taskIndex, task);
    });

    console.log("Monitoring for new tasks...");
};

const main = async (): Promise<void> => {
    await registerOperator();
    monitorNewTasks().catch((error) => {
        console.error("Error monitoring tasks:", error);
    });
};

main().catch((error) => {
    console.error("Error in main function:", error);
});