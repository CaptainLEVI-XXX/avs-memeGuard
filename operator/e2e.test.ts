import { createAnvil, Anvil } from "@viem/anvil";
import { describe, beforeAll, afterAll, it, expect } from '@jest/globals';
import { exec } from 'child_process';
import fs from 'fs/promises';
import path from 'path';
import util from 'util';
import { ethers } from "ethers";
import * as dotenv from "dotenv";

dotenv.config();

const execAsync = util.promisify(exec);

async function loadJsonFile(filePath: string): Promise<any> {
  try {
    const content = await fs.readFile(filePath, 'utf-8');
    return JSON.parse(content);
  } catch (error) {
    console.error(`Error loading file ${filePath}:`, error);
    return null;
  }
}

async function loadDeployments() {
  const coreFilePath = path.join(__dirname, '..', 'contracts', 'deployments', 'core', '31337.json');
  const memeGuardFilePath = path.join(__dirname, '..', 'contracts', 'deployments', 'memeguard', '31337.json');

  const [coreDeployment, memeGuardDeployment] = await Promise.all([
    loadJsonFile(coreFilePath),
    loadJsonFile(memeGuardFilePath)
  ]);

  if (!coreDeployment || !memeGuardDeployment) {
    console.error('Error loading deployments');
    return {};
  }

  return {
    core: coreDeployment,
    memeguard: memeGuardDeployment
  };
}

describe('Operator Functionality', () => {
  let anvil:Anvil;
  let deployment: Record<string, any>;
  let provider:ethers.JsonRpcProvider;
  let signer:ethers.Wallet;
  let delegationManager:ethers.Contract;
  let memeGuardServiceManager:ethers.Contract;
  let ecdsaRegistryContract:ethers.Contract;
  let avsDirectory:ethers.Contract;

  beforeAll(async () => {
    anvil = createAnvil();
    await anvil.start();
    await execAsync('npm run deploy:core');
    await execAsync('npm run deploy:memeguard');
    deployment = await loadDeployments();

    provider = new ethers.JsonRpcProvider(process.env.RPC_URL);
    signer = new ethers.Wallet(process.env.PRIVATE_KEY!, provider);

    const delegationManagerABI = await loadJsonFile(path.join(__dirname, '..', 'abis', 'IDelegationManager.json'));
    const ecdsaRegistryABI = await loadJsonFile(path.join(__dirname, '..', 'abis', 'ECDSAStakeRegistry.json'));
    const memeGuardServiceManagerABI = await loadJsonFile(path.join(__dirname, '..', 'abis', 'MemeGuardServiceManager.json'));
    const avsDirectoryABI = await loadJsonFile(path.join(__dirname, '..', 'abis', 'IAVSDirectory.json'));

    delegationManager = new ethers.Contract(deployment.core.addresses.delegationManager, delegationManagerABI, signer);
    memeGuardServiceManager = new ethers.Contract(deployment.memeguard.addresses.memeGuardServiceManager, memeGuardServiceManagerABI, signer);
    ecdsaRegistryContract = new ethers.Contract(deployment.memeguard.addresses.stakeRegistry, ecdsaRegistryABI, signer);
    avsDirectory = new ethers.Contract(deployment.core.addresses.avsDirectory, avsDirectoryABI, signer);
  });

  it('should register as an operator', async () => {
    const tx = await delegationManager.registerAsOperator(
      "0x0000000000000000000000000000000000000000",
      0,
      ""
    );
    await tx.wait();

    const isOperator = await delegationManager.isOperator(signer.address);
    expect(isOperator).toBe(true);
  });

  it('should register operator to AVS', async () => {
    const salt = ethers.hexlify(ethers.randomBytes(32));
    const expiry = Math.floor(Date.now() / 1000) + 3600;

    const operatorDigestHash = await avsDirectory.calculateOperatorAVSRegistrationDigestHash(
      signer.address,
      await memeGuardServiceManager.getAddress(),
      salt,
      expiry
    );

    const operatorSigningKey = new ethers.SigningKey(process.env.PRIVATE_KEY!);
    const operatorSignedDigestHash = operatorSigningKey.sign(operatorDigestHash);
    const operatorSignature = ethers.Signature.from(operatorSignedDigestHash).serialized;

    const tx = await ecdsaRegistryContract.registerOperatorWithSignature(
      {
        signature: operatorSignature,
        salt: salt,
        expiry: expiry
      },
      signer.address
    );
    await tx.wait();

    const isRegistered = await ecdsaRegistryContract.operatorRegistered(signer.address);
    expect(isRegistered).toBe(true);
  });

  it('should create a new task', async () => {
    const assessmentType = "token";
    const targetId = ethers.keccak256(ethers.toUtf8Bytes("TestToken"));
    const targetAddress = "0x95aD61b0a150d79219dCF64E1E6Cc01f0B64C4cE";

    const tx = await memeGuardServiceManager.createAssessmentTask(
      assessmentType,
      targetId,
      targetAddress
    );
    await tx.wait();
  });

  it('should sign and respond to a task', async () => {
    const taskIndex = 0;
    const taskCreatedBlock = await provider.getBlockNumber();
    const assessmentType = "token";
    const targetId = ethers.keccak256(ethers.toUtf8Bytes("TestToken"));
    const targetAddress = "0x95aD61b0a150d79219dCF64E1E6Cc01f0B64C4cE";
    
    // Risk assessment data
    const riskScore = 42; // Example risk score
    const isCritical = false; // Not critical
    const reportHash = "QmTestReportHash"; // Example IPFS hash for report
    
    // Create message hash
    const messageHash = ethers.solidityPackedKeccak256(
      ["string", "bytes32", "uint8", "bool", "string"],
      [assessmentType, targetId, riskScore, isCritical, reportHash]
    );
    const messageBytes = ethers.getBytes(messageHash);
    const signature = await signer.signMessage(messageBytes);
    
    // Create the task object
    const task = {
      assessmentType: assessmentType,
      targetId: targetId,
      targetAddress: targetAddress,
      taskCreatedBlock: taskCreatedBlock
    };
    
    // Respond to task
    const tx = await memeGuardServiceManager.respondToAssessment(
      task,
      taskIndex,
      signature,
      riskScore,
      isCritical,
      reportHash
    );
    await tx.wait();
  });

  afterAll(async () => {
    await anvil.stop();
  });
});