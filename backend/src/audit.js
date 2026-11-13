import crypto from 'node:crypto';
import { AuditEvent } from './models.js';
import { createCommitment } from './security.js';
import { publishAudit } from './blockchain.js';
import { config } from './config.js';
export async function queueAudit(user, eventType, version) {
  const credentialId = user.opaqueCredentialId;
  const nonce = '0x' + crypto.randomBytes(32).toString('hex');
  const commitment = createCommitment(credentialId, version, nonce);
  const eventId = `${user._id}:${version}:${eventType}`;
  return AuditEvent.findOneAndUpdate({ eventId }, { $setOnInsert: { eventId, user: user._id, eventType, credentialId, version, nonce, commitment, status: 'pending', nextAttemptAt: new Date() } }, { upsert: true, new: true });
}
let workerTimer;
let batchRunning = false;
export async function processAuditBatch() {
  if (batchRunning) return;
  batchRunning = true;
  try {
    const now = new Date();
    await AuditEvent.updateMany(
      { status: 'processing', updatedAt: { $lt: new Date(Date.now() - 120000) } },
      { $set: { status: 'retrying', nextAttemptAt: now } }
    );
    // Keep versions in order: a later version must not leapfrog an in-flight transaction.
    if (await AuditEvent.exists({ status: 'processing' })) return;
    const job = await AuditEvent.findOneAndUpdate(
      { status: { $in: ['pending','retrying'] }, nextAttemptAt: { $lte: now }, attempts: { $lt: config.chain.maxAttempts } },
      { $set: { status: 'processing' }, $inc: { attempts: 1 } }, { sort: { createdAt: 1 }, new: true }
    ).select('+credentialId +nonce');
    if (!job) return;
    try {
      const result = await publishAudit(job);
      job.status = 'confirmed'; job.transactionHash = result.hash || job.transactionHash;
      job.blockNumber = result.blockNumber || job.blockNumber; job.lastErrorCode = undefined;
    } catch (error) {
      const code = String(error.message || 'AUDIT_ERROR');
      const transient = code === 'BLOCKCHAIN_NOT_CONFIGURED' || /network|timeout|ECONN|could not coalesce|socket|fetch failed|SERVER_ERROR|NETWORK_ERROR|could not detect/i.test(code);
      job.status = transient || job.attempts < config.chain.maxAttempts ? 'retrying' : 'failed';
      if (transient) job.attempts = 0;
      job.lastErrorCode = code.replace(/[^A-Z0-9_]/gi,'').slice(0,64);
      job.nextAttemptAt = new Date(Date.now() + (transient ? 60000 : Math.min(300000, 1000 * (2 ** job.attempts))));
    }
    await job.save();
  } finally {
    batchRunning = false;
  }
}
export function startAuditWorker() {
  if (workerTimer) return;
  workerTimer = setInterval(() => processAuditBatch().catch(() => {}), config.chain.interval);
  workerTimer.unref?.();
}
