import dotenv from 'dotenv';
dotenv.config({ path: process.env.ENV_FILE || '../.env' });
export const config = {
  nodeEnv: process.env.NODE_ENV || 'development',
  port: Number(process.env.PORT || 4000),
  origin: process.env.FRONTEND_ORIGIN || 'http://localhost:5173',
  mongoUri: process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/blockchain_password_security',
  cookieName: process.env.COOKIE_NAME || 'bps_session',
  cookieSecure: process.env.COOKIE_SECURE === 'true',
  sessionTtlMs: Number(process.env.SESSION_TTL_HOURS || 12) * 3600000,
  csrfSecret: process.env.CSRF_SECRET || 'development-only-change-this-secret-32chars',
  resetTtlMs: Number(process.env.RESET_TOKEN_TTL_MINUTES || 20) * 60000,
  argon2: { memoryCost: Math.max(19456, Number(process.env.ARGON2_MEMORY_KIB || 19456)), timeCost: Math.max(2, Number(process.env.ARGON2_TIME_COST || 2)), parallelism: Math.max(1, Number(process.env.ARGON2_PARALLELISM || 1)) },
  chain: { enabled: process.env.BLOCKCHAIN_ENABLED !== 'false', rpc: process.env.BLOCKCHAIN_RPC_URL, privateKey: process.env.BLOCKCHAIN_PRIVATE_KEY, chainId: Number(process.env.BLOCKCHAIN_CHAIN_ID || 31337), address: process.env.BLOCKCHAIN_CONTRACT_ADDRESS, interval: Number(process.env.AUDIT_WORKER_INTERVAL_MS || 5000), maxAttempts: Number(process.env.AUDIT_MAX_ATTEMPTS || 8) }
};
