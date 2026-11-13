import mongoose from 'mongoose';
const { Schema, model } = mongoose;
const userSchema = new Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true, maxlength: 254 },
  passwordHash: { type: String, required: true, select: false },
  opaqueCredentialId: { type: String, required: true, unique: true, select: false },
  credentialVersion: { type: Number, required: true, default: 1, min: 1 }
}, { timestamps: true, optimisticConcurrency: true });
const sessionSchema = new Schema({
  user: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  sessionHash: { type: String, required: true, unique: true },
  csrfHash: { type: String, required: true },
  expiresAt: { type: Date, required: true, index: { expires: 0 } },
  revokedAt: { type: Date, default: null }
}, { timestamps: true });
const auditSchema = new Schema({
  eventId: { type: String, required: true, unique: true },
  user: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  eventType: { type: String, enum: ['REGISTERED','UPDATED','REVOKED'], required: true },
  credentialId: { type: String, required: true, select: false },
  version: { type: Number, required: true },
  nonce: { type: String, required: true, select: false },
  commitment: { type: String, required: true },
  status: { type: String, enum: ['pending','processing','retrying','confirmed','failed'], default: 'pending', index: true },
  transactionHash: String, blockNumber: Number, attempts: { type: Number, default: 0 },
  nextAttemptAt: { type: Date, default: Date.now }, lastErrorCode: String
}, { timestamps: true });
auditSchema.index({ user: 1, version: 1, eventType: 1 }, { unique: true });
const resetSchema = new Schema({
  user: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  tokenHash: { type: String, required: true, unique: true },
  expiresAt: { type: Date, required: true, index: { expires: 0 } },
  usedAt: { type: Date, default: null }
}, { timestamps: true });
export const User = model('User', userSchema);
export const Session = model('Session', sessionSchema);
export const AuditEvent = model('AuditEvent', auditSchema);
export const PasswordResetToken = model('PasswordResetToken', resetSchema);
