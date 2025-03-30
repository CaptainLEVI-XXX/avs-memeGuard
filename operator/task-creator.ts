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

// Load deployment data from the correct folder
const avsDeploymentData = JSON.parse(fs.readFileSync(path.resolve(__dirname, `../contracts/deployments/hello-world/${chainId}.json`), 'utf8'));
// Load core deployment data
const coreDeploymentData = JSON.parse(fs.readFileSync(path.resolve(__dirname, `../contracts/deployments/core/${chainId}.json`), 'utf8'));

const delegationManagerAddress = coreDeploymentData.addresses.delegationManager; 
const avsDirectoryAddress = coreDeploymentData.addresses.avsDirectory;
const memeGuardServiceManagerAddress = avsDeploymentData.addresses.memeGuardServiceManager;
const ecdsaStakeRegistryAddress = avsDeploymentData.addresses.stakeRegistry;

console.log("Contract Addresses:");
console.log(`- AVS Directory: ${avsDirectoryAddress}`);
console.log(`- MemeGuard Service Manager: ${memeGuardServiceManagerAddress}`);
console.log(`- ECDSA Stake Registry: ${ecdsaStakeRegistryAddress}`);
console.log(`- Delegation Manager: ${delegationManagerAddress}`);

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

    try {
        // Generate salt and expiry
        const salt = ethers.hexlify(ethers.randomBytes(32));
        const expiry = Math.floor(Date.now() / 1000) + 3600; // Example expiry, 1 hour from now
        
        console.log("Registration parameters:");
        console.log(`- Operator address: ${wallet.address}`);
        console.log(`- AVS address: ${await memeGuardServiceManager.getAddress()}`);
        console.log(`- Salt: ${salt}`);
        console.log(`- Expiry: ${expiry}`);
        
        // Check if function exists in ABI
        const functionFragment = avsDirectory.interface.getFunction("calculateOperatorAVSRegistrationDigestHash");
        if (functionFragment) {
            console.log("Function signature:", functionFragment.format());
        } else {
            console.log("Function 'calculateOperatorAVSRegistrationDigestHash' not found in ABI!");
        }
        
        // Check ABI for AVS Directory
        console.log("AVS Directory ABI functions:");
        avsDirectory.interface.fragments.forEach((fragment: any) => {
            if (fragment.type === "function") {
                console.log(`- ${fragment.name}(${fragment.inputs.map((input: any) => input.type).join(',')})`);
            }
        });
        
        console.log("Calling calculateOperatorAVSRegistrationDigestHash...");
        
        // Define the output structure
        let operatorSignatureWithSaltAndExpiry = {
            signature: "",
            salt: salt,
            expiry: expiry
        };
        
        // Try a more generic approach if direct call fails
        let operatorDigestHash;
        try {
            operatorDigestHash = await avsDirectory.calculateOperatorAVSRegistrationDigestHash(
                wallet.address,
                await memeGuardServiceManager.getAddress(),
                salt,
                expiry
            );
        } catch (error) {
            console.error("Error calling calculateOperatorAVSRegistrationDigestHash:", error);
            
            // Alternative: Try directly submitting to ECDSAStakeRegistry
            console.log("Attempting direct registration without digest hash calculation");
            
            // Create a generic signature (this is not secure but might work for local testing)
            const message = ethers.solidityPackedKeccak256(
                ["address", "address", "bytes32", "uint256"],
                [wallet.address, await memeGuardServiceManager.getAddress(), salt, expiry]
            );
            const messageBytes = ethers.getBytes(message);
            const signature = await wallet.signMessage(messageBytes);
            operatorSignatureWithSaltAndExpiry.signature = signature;
            
            const tx2 = await ecdsaRegistryContract.registerOperatorWithSignature(
                operatorSignatureWithSaltAndExpiry,
                wallet.address
            );
            await tx2.wait();
            console.log("Operator registered on AVS successfully (direct method)");
            return;
        }
        
        console.log("Digest hash calculated:", operatorDigestHash);

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
    } catch (error) {
        console.error("Error during AVS registration:", error);
        throw error;
    }
};

const monitorNewTasks = async (): Promise<void> => {
    memeGuardServiceManager.on("NewTaskCreated", async (taskIndex: number, task: Task) => {
        console.log(`New task detected: ${task.assessmentType} assessment for target ${task.targetId}`);
        await signAndRespondToTask(taskIndex, task);
    });

    console.log("Monitoring for new tasks...");
};

const main = async (): Promise<void> => {
    try {
        // Let's validate contracts first
        console.log("Validating contracts...");
        
        // Check AVS Directory contract
        try {
            const avsDirectoryCode = await provider.getCode(avsDirectoryAddress);
            console.log(`AVS Directory contract code exists: ${avsDirectoryCode !== '0x'}`);
        } catch (error) {
            console.error("Error checking AVS Directory contract:", error);
        }
        
        // Check MemeGuard contract
        try {
            const memeGuardCode = await provider.getCode(memeGuardServiceManagerAddress);
            console.log(`MemeGuard contract code exists: ${memeGuardCode !== '0x'}`);
        } catch (error) {
            console.error("Error checking MemeGuard contract:", error);
        }
        
        // Now proceed with registration
        await registerOperator();
        monitorNewTasks().catch((error) => {
            console.error("Error monitoring tasks:", error);
        });
    } catch (error) {
        console.error("Error in main function:", error);
    }
};

main().catch((error) => {
    console.error("Unhandled error:", error);
});