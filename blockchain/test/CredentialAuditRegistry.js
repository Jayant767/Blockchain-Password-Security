import { expect } from 'chai';
import { ethers } from 'hardhat';
describe('CredentialAuditRegistry', function () {
  async function setup() {
    const [owner, writer, stranger] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory('CredentialAuditRegistry');
    const registry = await Factory.deploy(); await registry.waitForDeployment();
    await registry.setWriter(writer.address, true);
    return { registry, owner, writer, stranger };
  }
  it('registers a credential and emits an event', async()=>{
    const {registry,writer}=await setup(); const id=ethers.id('opaque-id'), commitment=ethers.id('commitment');
    await expect(registry.connect(writer).registerCredential(id,1,commitment)).to.emit(registry,'CredentialRegistered').withArgs(id,1,commitment);
    const data=await registry.getCredential(id); expect(data.version).to.equal(1); expect(data.commitment).to.equal(commitment);
  });
  it('rejects unauthorized writers',async()=>{
    const {registry,stranger}=await setup();
    await expect(registry.connect(stranger).registerCredential(ethers.id('id'),1,ethers.id('c'))).to.be.revertedWithCustomError(registry,'Unauthorized');
  });
  it('enforces sequential versions and prevents duplicates',async()=>{
    const {registry,writer}=await setup(); const id=ethers.id('id');
    await registry.connect(writer).registerCredential(id,1,ethers.id('c1'));
    await expect(registry.connect(writer).registerCredential(id,1,ethers.id('c1'))).to.be.revertedWithCustomError(registry,'AlreadyRegistered');
    await expect(registry.connect(writer).updateCredential(id,3,ethers.id('c3'))).to.be.revertedWithCustomError(registry,'InvalidVersion');
    await registry.connect(writer).updateCredential(id,2,ethers.id('c2'));
    expect((await registry.getCredential(id)).version).to.equal(2);
  });
  it('revokes and prevents subsequent updates',async()=>{
    const {registry,writer}=await setup(); const id=ethers.id('id');
    await registry.connect(writer).registerCredential(id,1,ethers.id('c1'));
    await registry.connect(writer).revokeCredential(id);
    await expect(registry.connect(writer).updateCredential(id,2,ethers.id('c2'))).to.be.revertedWithCustomError(registry,'AlreadyRevoked');
  });
});
