import { ethers } from "ethers"; 
import * as dotenv from "dotenv"; 
const fs = require('fs'); 
const path = require('path'); 
dotenv.config();  

// Setup env variables 
const provider = new ethers.JsonRpcProvider(process.env.RPC_URL); 
const wallet = new ethers.Wallet(process.env.PRIVATE_KEY!, provider); 
/// TODO: Hack 
let chainId = 31337;  

const avsDeploymentData = JSON.parse(fs.readFileSync(path.resolve(__dirname, `../contracts/deployments/hello-world/${chainId}.json`), 'utf8')); 
const memeGuardServiceManagerAddress = avsDeploymentData.addresses.memeGuardServiceManager; 
const memeGuardServiceManagerABI = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../abis/MemeGuardServiceManager.json'), 'utf8')); 
// Initialize contract objects from ABIs 
const memeGuardServiceManager = new ethers.Contract(memeGuardServiceManagerAddress, memeGuardServiceManagerABI, wallet);   

// Function to generate assessment type and target
function generateAssessmentData() {
    const crypto = require('crypto');
    const assessmentTypes = ["token", "strategy", "transition"];
    const assessmentType = assessmentTypes[Math.floor(Math.random() * assessmentTypes.length)];
    
    // Generate random target ID and address
    const targetName = `Target${Math.floor(Math.random() * 10000)}`;
    const targetId = ethers.keccak256(ethers.toUtf8Bytes(targetName));
    const targetAddress = "0x" + crypto.randomBytes(20).toString('hex');
    
    return { assessmentType, targetId, targetAddress, name: targetName };
}

async function createNewTask() {
  try {
    const taskData = generateAssessmentData();
    console.log(`Creating new ${taskData.assessmentType} assessment for ${taskData.name}`);
    
    // Send a transaction to create a new assessment task
    const tx = await memeGuardServiceManager.createAssessmentTask(
      taskData.assessmentType,
      taskData.targetId,
      taskData.targetAddress
    );
        
    // Wait for the transaction to be mined
    const receipt = await tx.wait();
        
    console.log(`Transaction successful with hash: ${receipt.hash}`);
  } catch (error) {
    console.error('Error sending transaction:', error);
  }
}

// Function to create a new task with random data every 24 seconds
function startCreatingTasks() {
  setInterval(() => {
    createNewTask();
  }, 24000);
}

// Start the process
startCreatingTasks();