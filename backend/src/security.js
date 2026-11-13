import crypto from 'node:crypto';
import argon2 from 'argon2';
import { AbiCoder, keccak256, toUtf8Bytes } from 'ethers';
import { config } from './config.js';
export const randomToken = (bytes=32) => crypto.randomBytes(bytes).toString('base64url');
export const sha256 = value => crypto.createHash('sha256').update(value).digest('hex');
export const hashPassword = password => argon2.hash(password, { type: argon2.argon2id, memoryCost: config.argon2.memoryCost, timeCost: config.argon2.timeCost, parallelism: config.argon2.parallelism });
export const verifyPassword = (hash, password) => argon2.verify(hash, password);
export function passwordPolicy(password) {
  return typeof password === 'string' && Buffer.byteLength(password, 'utf8') >= 12 &&
    Buffer.byteLength(password, 'utf8') <= 1024 && password.length >= 12;
}
export function createCommitment(credentialId, version, nonce) {
  // Match Solidity abi.encode(bytes32,bytes32,uint64,bytes32) exactly.
  const domain = keccak256(toUtf8Bytes('BPS_CREDENTIAL_AUDIT_V1'));
  return keccak256(AbiCoder.defaultAbiCoder().encode(['bytes32','bytes32','uint64','bytes32'], [domain, credentialId, version, nonce]));
}
