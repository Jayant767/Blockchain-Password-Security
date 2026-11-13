import { JsonRpcProvider, Wallet, Contract } from 'ethers';
import { config } from './config.js';
const abi = [
 'function registerCredential(bytes32 credentialId,uint64 version,bytes32 commitment) external',
 'function updateCredential(bytes32 credentialId,uint64 version,bytes32 commitment) external',
 'function revokeCredential(bytes32 credentialId) external',
 'function getCredential(bytes32 credentialId) external view returns (uint64 version,bytes32 commitment,bool revoked,uint64 updatedAt)',
 'event CredentialRegistered(bytes32 indexed credentialId,uint64 version,bytes32 commitment)',
 'event CredentialUpdated(bytes32 indexed credentialId,uint64 version,bytes32 commitment)',
 'event CredentialRevoked(bytes32 indexed credentialId,uint64 version)'
];
let provider, signer, contract;
export function getContract() {
  if (!config.chain.enabled || !config.chain.rpc || !config.chain.privateKey || !config.chain.address) throw new Error('BLOCKCHAIN_NOT_CONFIGURED');
  if (!contract) {
    provider = new JsonRpcProvider(config.chain.rpc);
    signer = new Wallet(config.chain.privateKey, provider);
    contract = new Contract(config.chain.address, abi, signer);
  }
  return contract;
}
async function ensureExpectedNetwork(c) {
  const network = await c.runner.provider.getNetwork();
  if (Number(network.chainId) !== config.chain.chainId) throw new Error('CHAIN_ID_MISMATCH');
  return network;
}
async function findPublishedEvent(c, event) {
  const [registered, updated] = await Promise.all([
    c.queryFilter(c.filters.CredentialRegistered(event.credentialId), 0, 'latest'),
    c.queryFilter(c.filters.CredentialUpdated(event.credentialId), 0, 'latest')
  ]);
  return [...registered, ...updated].find(log =>
    Number(log.args.version) === event.version &&
    log.args.commitment.toLowerCase() === event.commitment.toLowerCase()
  );
}
export async function publishAudit(event) {
  const c = getContract();
  await ensureExpectedNetwork(c);
  const onChain = await c.getCredential(event.credentialId);
  let tx;
  if (Number(onChain.version) === 0) {
    if (event.version !== 1) throw new Error('CHAIN_VERSION_GAP');
    tx = await c.registerCredential(event.credentialId, event.version, event.commitment);
  } else {
    if (Number(onChain.version) >= event.version) {
      const log = await findPublishedEvent(c, event);
      if (log) return { hash: log.transactionHash, blockNumber: log.blockNumber, alreadyApplied: true };
      throw new Error('CHAIN_VERSION_CONFLICT');
    }
    if (Number(onChain.version) + 1 !== event.version) throw new Error('CHAIN_VERSION_GAP');
    tx = await c.updateCredential(event.credentialId, event.version, event.commitment);
  }
  const receipt = await tx.wait(1);
  if (!receipt || receipt.status !== 1) throw new Error('TX_NOT_CONFIRMED');
  const finalState = await c.getCredential(event.credentialId);
  if (Number(finalState.version) !== event.version || finalState.commitment.toLowerCase() !== event.commitment.toLowerCase()) throw new Error('CHAIN_STATE_MISMATCH');
  return { hash: receipt.hash, blockNumber: receipt.blockNumber, alreadyApplied: false };
}
export async function chainStatus() {
  try {
    const c = getContract(); const network = await c.runner.provider.getNetwork();
    const chainId = Number(network.chainId);
    if (chainId !== config.chain.chainId) return { available: false, chainId, expectedChainId: config.chain.chainId, contractAddress: config.chain.address, reason: 'chain_id_mismatch' };
    return { available: true, chainId, contractAddress: config.chain.address };
  } catch (e) {
    return { available: false, chainId: config.chain.chainId, contractAddress: config.chain.address || null, reason: e.message === 'BLOCKCHAIN_NOT_CONFIGURED' ? 'not_configured' : 'rpc_unavailable' };
  }
}
export async function verifyAudit(event) {
  const c = getContract();
  await ensureExpectedNetwork(c);
  const result = await c.getCredential(event.credentialId);
  // Current mapping only retains the latest version; event logs preserve prior versions.
  const published = Boolean(await findPublishedEvent(c, event));
  return { exists: published, version: Number(result.version), commitmentMatches: published, revoked: result.revoked, updatedAt: Number(result.updatedAt) };
}
