import 'express-async-errors';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import crypto from 'node:crypto';
import { z } from 'zod';
import { User, Session, AuditEvent, PasswordResetToken } from './models.js';
import { config } from './config.js';
import { randomToken, sha256, hashPassword, verifyPassword, passwordPolicy } from './security.js';
import { queueAudit } from './audit.js';
import { chainStatus, verifyAudit } from './blockchain.js';

export const app = express();
app.disable('x-powered-by');
app.use(helmet());
app.use(cors({ origin: config.origin, credentials: true }));
app.use(express.json({ limit: '12kb' }));
app.use(cookieParser());
app.use((req,res,next)=>{
  if (['GET','HEAD','OPTIONS'].includes(req.method)) return next();
  const origin=req.get('origin');
  if (origin && origin !== config.origin) return fail(res,403,'ORIGIN_INVALID','Request origin is not allowed');
  next();
});
app.use(rateLimit({ windowMs: 15*60*1000, limit: 300, standardHeaders: true, legacyHeaders: false }));
const authLimiter = rateLimit({ windowMs: 15*60*1000, limit: 12, standardHeaders: true, legacyHeaders: false });
// Equalize the expensive password-verification path for unknown accounts.
const dummyPasswordHash = hashPassword('not-a-real-account-password-for-timing-equalization');
const cookieOptions = () => ({ httpOnly: true, secure: config.cookieSecure, sameSite: 'strict', path: '/', maxAge: config.sessionTtlMs });
const csrfCookieOptions = () => ({ httpOnly: false, secure: config.cookieSecure, sameSite: 'strict', path: '/', maxAge: config.sessionTtlMs });
const fail = (res, status, code, message) => res.status(status).json({ error: { code, message } });
function validate(schema) { return (req,res,next) => { const parsed=schema.safeParse(req.body); if(!parsed.success) return fail(res,400,'VALIDATION_ERROR',parsed.error.issues[0]?.message || 'Invalid input'); req.body=parsed.data; next(); }; }
const emailSchema = z.string().trim().email().max(254).transform(v=>v.toLowerCase());
const passwordSchema = z.string().min(12).max(1024).refine(passwordPolicy,'Password must be at least 12 characters and at most 1024 UTF-8 bytes');
const authSchema = z.object({ email: emailSchema, password: passwordSchema });
function setCsrf(res, token) { res.cookie('bps_csrf', token, csrfCookieOptions()); }
async function createSession(res, user) {
  const sid=randomToken(32), csrf=randomToken(32);
  await Session.create({ user: user._id, sessionHash: sha256(sid), csrfHash: sha256(`${config.csrfSecret}:${csrf}`), expiresAt: new Date(Date.now()+config.sessionTtlMs) });
  res.cookie(config.cookieName,sid,cookieOptions()); setCsrf(res,csrf);
}
async function revokeSessions(userId) { await Session.updateMany({ user:userId, revokedAt:null }, { $set:{revokedAt:new Date()} }); }
async function requireAuth(req,res,next) {
  try {
    const sid=req.cookies[config.cookieName]; if(!sid) return fail(res,401,'UNAUTHENTICATED','Authentication required');
    const session=await Session.findOne({sessionHash:sha256(sid),revokedAt:null,expiresAt:{$gt:new Date()}}).populate('user');
    if(!session || !session.user) return fail(res,401,'UNAUTHENTICATED','Authentication required');
    req.user=session.user; req.session=session; next();
  } catch { fail(res,500,'INTERNAL_ERROR','Request could not be completed'); }
}
function requireCsrf(req,res,next) {
  const cookie=req.cookies.bps_csrf, header=req.get('x-csrf-token');
  if(!cookie || !header || cookie!==header || sha256(header)!==req.session.csrfHash) return fail(res,403,'CSRF_INVALID','CSRF validation failed');
  next();
}
const publicUser = user => ({ id:user._id, email:user.email, credentialVersion:user.credentialVersion, createdAt:user.createdAt });
app.get('/api/health',(req,res)=>res.json({ok:true}));
app.post('/api/auth/register',authLimiter,validate(authSchema),async(req,res)=>{
  try {
    const passwordHash=await hashPassword(req.body.password);
    const user=await User.create({email:req.body.email,passwordHash,opaqueCredentialId:'0x'+crypto.randomBytes(32).toString('hex'),credentialVersion:1});
    await queueAudit(user,'REGISTERED',1); await createSession(res,user);
    res.status(201).json({user:publicUser(user),auditStatus:'pending'});
  } catch(e) { if(e.code===11000) return fail(res,409,'ACCOUNT_EXISTS','An account with this email already exists'); fail(res,500,'REGISTRATION_FAILED','Registration could not be completed'); }
});
app.post('/api/auth/login',authLimiter,validate(authSchema),async(req,res)=>{
  try {
    const user=await User.findOne({email:req.body.email}).select('+passwordHash');
    const comparisonHash=user ? user.passwordHash : await dummyPasswordHash;
    const passwordMatches=await verifyPassword(comparisonHash,req.body.password).catch(()=>false);
    if(!user || !passwordMatches) return fail(res,401,'INVALID_CREDENTIALS','Email or password is incorrect');
    await revokeSessions(user._id); await createSession(res,user);
    res.json({user:publicUser(user)});
  } catch { fail(res,500,'LOGIN_FAILED','Login could not be completed'); }
});
app.post('/api/auth/logout',requireAuth,requireCsrf,async(req,res)=>{
  await Session.updateOne({_id:req.session._id},{$set:{revokedAt:new Date()}});
  res.clearCookie(config.cookieName,{path:'/'}); res.clearCookie('bps_csrf',{path:'/'}); res.status(204).end();
});
app.post('/api/auth/change-password',requireAuth,requireCsrf,validate(z.object({currentPassword:z.string().min(1).max(1024),newPassword:passwordSchema})),async(req,res)=>{
  const user=await User.findById(req.user._id).select('+passwordHash +opaqueCredentialId');
  if(!await verifyPassword(user.passwordHash,req.body.currentPassword).catch(()=>false)) return fail(res,401,'INVALID_CREDENTIALS','Current password is incorrect');
  user.passwordHash=await hashPassword(req.body.newPassword); user.credentialVersion+=1; await user.save();
  await revokeSessions(user._id); await PasswordResetToken.updateMany({user:user._id,usedAt:null},{$set:{usedAt:new Date()}}); await queueAudit(user,'UPDATED',user.credentialVersion); await createSession(res,user);
  res.json({user:publicUser(user),auditStatus:'pending'});
});
app.post('/api/auth/forgot-password',authLimiter,validate(z.object({email:emailSchema})),async(req,res)=>{
  const user=await User.findOne({email:req.body.email});
  const response={message:'If an account exists, password reset instructions have been issued.'};
  if(user) {
    await PasswordResetToken.updateMany({user:user._id,usedAt:null},{$set:{usedAt:new Date()}});
    const token=randomToken(32);
    await PasswordResetToken.create({user:user._id,tokenHash:sha256(token),expiresAt:new Date(Date.now()+config.resetTtlMs)});
    if(config.nodeEnv!=='production') response.resetUrl=`http://localhost:5173/reset-password?token=${encodeURIComponent(token)}`;
  }
  res.status(202).json(response);
});
app.post('/api/auth/reset-password',authLimiter,validate(z.object({token:z.string().min(20).max(200),newPassword:passwordSchema})),async(req,res)=>{
  const record=await PasswordResetToken.findOneAndUpdate(
    {tokenHash:sha256(req.body.token),usedAt:null,expiresAt:{$gt:new Date()}},
    {$set:{usedAt:new Date()}},{new:true}
  );
  if(!record) return fail(res,400,'RESET_TOKEN_INVALID','Reset token is invalid or expired');
  const user=await User.findById(record.user).select('+opaqueCredentialId');
  user.passwordHash=await hashPassword(req.body.newPassword); user.credentialVersion+=1; await user.save();
  await revokeSessions(user._id); await queueAudit(user,'UPDATED',user.credentialVersion);
  res.json({message:'Password has been reset. Please sign in.'});
});
app.get('/api/users/me',requireAuth,(req,res)=>res.json({user:publicUser(req.user)}));
app.get('/api/audit/history',requireAuth,async(req,res)=>{
  const events=await AuditEvent.find({user:req.user._id}).sort({createdAt:-1}).select('-nonce -credentialId');
  res.json({events});
});
app.get('/api/blockchain/status',async(req,res)=>res.json(await chainStatus()));
app.get('/api/blockchain/verify',requireAuth,async(req,res)=>{
  const events=await AuditEvent.find({user:req.user._id}).sort({version:-1}).select('+credentialId +nonce');
  const results=[];
  for(const event of events) {
    try { results.push({eventId:event.eventId,version:event.version,commitment:event.commitment,status:event.status,transactionHash:event.transactionHash||null,verification:await verifyAudit(event)}); }
    catch(e) { results.push({eventId:event.eventId,version:event.version,commitment:event.commitment,status:event.status,transactionHash:event.transactionHash||null,verification:{available:false,reason:'rpc_unavailable_or_not_configured'}}); }
  }
  res.json({events:results});
});
app.use((err,req,res,next)=>{ res.status(500).json({error:{code:'INTERNAL_ERROR',message:'Request could not be completed'}}); });
