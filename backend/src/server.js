import mongoose from 'mongoose';
import { app } from './app.js';
import { config } from './config.js';
import { startAuditWorker } from './audit.js';
try {
  await mongoose.connect(config.mongoUri);
  app.listen(config.port,()=>console.log(`BPS API listening on http://localhost:${config.port}`));
  startAuditWorker();
} catch (error) {
  console.error('Startup failed: database connection unavailable');
  process.exit(1);
}
