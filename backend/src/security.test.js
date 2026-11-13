import { describe,it,expect } from 'vitest';
import { hashPassword, verifyPassword, passwordPolicy, createCommitment } from './security.js';
describe('password security primitives',()=>{
  it('hashes with Argon2id and verifies correct passwords',async()=>{
    const hash=await hashPassword('correct horse battery staple');
    expect(hash.startsWith('$argon2id$')).toBe(true);
    expect(await verifyPassword(hash,'correct horse battery staple')).toBe(true);
    expect(await verifyPassword(hash,'incorrect horse battery staple')).toBe(false);
  });
  it('rejects short and overlong passwords without truncation',()=>{
    expect(passwordPolicy('short')).toBe(false);
    expect(passwordPolicy('a'.repeat(1025))).toBe(false);
    expect(passwordPolicy('a'.repeat(20))).toBe(true);
  });
  it('creates deterministic commitments for the same inputs',()=>{
    const id='0x'+'11'.repeat(32), nonce='0x'+'22'.repeat(32);
    expect(createCommitment(id,1,nonce)).toBe(createCommitment(id,1,nonce));
    expect(createCommitment(id,1,nonce)).not.toBe(createCommitment(id,2,nonce));
  });
});
