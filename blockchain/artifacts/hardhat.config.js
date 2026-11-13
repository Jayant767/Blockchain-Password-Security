import '@nomicfoundation/hardhat-toolbox';
import dotenv from 'dotenv';
dotenv.config({ path: process.env.ENV_FILE || '../.env' });
const sepoliaRpc = process.env.SEPOLIA_RPC_URL;
const deployerKey = process.env.DEPLOYER_PRIVATE_KEY;
export default {
 solidity: { version: '0.8.24', settings: { optimizer: { enabled: true, runs: 200 } } },
 networks: {
   localhost: { url: process.env.BLOCKCHAIN_RPC_URL || 'http://127.0.0.1:8545', chainId: 31337 },
   ...(sepoliaRpc && deployerKey ? { sepolia: { url: sepoliaRpc, accounts: [deployerKey], chainId: 11155111 } } : {})
 }
};
