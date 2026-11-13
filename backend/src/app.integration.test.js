import { beforeAll, afterAll, beforeEach, describe, it, expect } from 'vitest';
import request from 'supertest';
import mongoose from 'mongoose';
import { app } from './app.js';
import { User, Session, AuditEvent, PasswordResetToken } from './models.js';
import { randomToken, sha256 } from './security.js';
import { queueAudit, processAuditBatch } from './audit.js';

const enabled = Boolean(process.env.TEST_MONGODB_URI);
const suite = describe.skipIf(!enabled);
const password = 'correct horse battery staple';
function csrfFrom(response) {
  const cookie = response.headers['set-cookie']?.find(v => v.startsWith('bps_csrf='));
  return cookie?.split(';')[0].slice('bps_csrf='.length);
}
suite('Mongo-backed authentication lifecycle', () => {
  beforeAll(async () => { await mongoose.connect(process.env.TEST_MONGODB_URI); });
  afterAll(async () => { await mongoose.connection.dropDatabase(); await mongoose.disconnect(); });
  beforeEach(async () => {
    await Promise.all([User.deleteMany({}),Session.deleteMany({}),AuditEvent.deleteMany({}),PasswordResetToken.deleteMany({})]);
  });

  it('registers, rejects duplicate email, logs in generically and rotates the session', async () => {
    const agent=request.agent(app);
    const first=await agent.post('/api/auth/register').send({email:'student@example.com',password});
    expect(first.status).toBe(201);
    const firstSid=first.headers['set-cookie'].find(v=>v.startsWith('bps_session='));
    const duplicate=await request(app).post('/api/auth/register').send({email:'student@example.com',password});
    expect(duplicate.status).toBe(409);
    const wrong=await request(app).post('/api/auth/login').send({email:'student@example.com',password:'incorrect horse battery staple'});
    expect(wrong.status).toBe(401);
    expect(wrong.body.error.message).toBe('Email or password is incorrect');
    const login=await agent.post('/api/auth/login').send({email:'student@example.com',password});
    const secondSid=login.headers['set-cookie'].find(v=>v.startsWith('bps_session='));
    expect(secondSid).not.toBe(firstSid);
    expect((await agent.get('/api/users/me')).status).toBe(200);
  });

  it('changes password, increments version, rotates session and rejects the old password', async () => {
    const agent=request.agent(app);
    const registered=await agent.post('/api/auth/register').send({email:'rotate@example.com',password});
    const csrf=csrfFrom(registered);
    const changed=await agent.post('/api/auth/change-password').set('X-CSRF-Token',csrf).send({currentPassword:password,newPassword:'a different strong passphrase 2026'});
    expect(changed.status).toBe(200);
    expect(changed.body.user.credentialVersion).toBe(2);
    expect((await agent.get('/api/users/me')).status).toBe(200);
    const oldLogin=await request(app).post('/api/auth/login').send({email:'rotate@example.com',password});
    expect(oldLogin.status).toBe(401);
    const newLogin=await request(app).post('/api/auth/login').send({email:'rotate@example.com',password:'a different strong passphrase 2026'});
    expect(newLogin.status).toBe(200);
  });

  it('deduplicates outbox events and keeps audit retrying when blockchain is unavailable', async () => {
    await request(app).post('/api/auth/register').send({email:'outbox@example.com',password});
    const user=await User.findOne({email:'outbox@example.com'}).select('+opaqueCredentialId');
    const first=await AuditEvent.findOne({user:user._id});
    const duplicate=await queueAudit(user,'REGISTERED',1);
    expect(duplicate.eventId).toBe(first.eventId);
    expect(await AuditEvent.countDocuments({user:user._id})).toBe(1);
    await processAuditBatch();
    const refreshed=await AuditEvent.findOne({user:user._id});
    expect(['retrying','pending']).toContain(refreshed.status);
  });

  it('logs out and revokes the session', async () => {
    const agent=request.agent(app);
    const registered=await agent.post('/api/auth/register').send({email:'logout@example.com',password});
    const response=await agent.post('/api/auth/logout').set('X-CSRF-Token',csrfFrom(registered)).send({});
    expect(response.status).toBe(204);
    expect((await agent.get('/api/users/me')).status).toBe(401);
  });

  it('rejects expired and reused reset tokens and revokes existing sessions', async () => {
    const agent=request.agent(app);
    const registered=await agent.post('/api/auth/register').send({email:'reset@example.com',password});
    const user=await User.findOne({email:'reset@example.com'});
    const expired=randomToken();
    await PasswordResetToken.create({user:user._id,tokenHash:sha256(expired),expiresAt:new Date(Date.now()-1000)});
    const expiredResponse=await request(app).post('/api/auth/reset-password').send({token:expired,newPassword:'new secure password 2026'});
    expect(expiredResponse.status).toBe(400);
    const token=randomToken();
    await PasswordResetToken.create({user:user._id,tokenHash:sha256(token),expiresAt:new Date(Date.now()+60000)});
    const reset=await request(app).post('/api/auth/reset-password').send({token,newPassword:'new secure password 2026'});
    expect(reset.status).toBe(200);
    const replay=await request(app).post('/api/auth/reset-password').send({token,newPassword:'another secure password 2026'});
    expect(replay.status).toBe(400);
    expect((await agent.get('/api/users/me')).status).toBe(401);
  });
});
