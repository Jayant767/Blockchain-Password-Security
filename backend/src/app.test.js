import { describe,it,expect } from 'vitest';
import request from 'supertest';
import mongoose from 'mongoose';
import { app } from './app.js';
import { User } from './models.js';
import { config } from './config.js';
describe('authentication API',()=>{
  it('validates malformed registration without database access',async()=>{
    const response=await request(app).post('/api/auth/register').send({email:'not-an-email',password:'short'});
    expect(response.status).toBe(400);
    expect(response.body.error.code).toBe('VALIDATION_ERROR');
  });
  it('returns blockchain status without requiring authentication',async()=>{
    const response=await request(app).get('/api/blockchain/status');
    expect(response.status).toBe(200);
    expect(typeof response.body.available).toBe('boolean');
  });
  it.skip('registers, authenticates and rotates a session against a real MongoDB instance',async()=>{
    await mongoose.connect(config.mongoUri);
    await User.deleteMany({email:/^test-/});
    const agent=request.agent(app);
    const registered=await agent.post('/api/auth/register').send({email:'test-bps@example.com',password:'correct horse battery staple'});
    expect(registered.status).toBe(201);
    const me=await agent.get('/api/users/me'); expect(me.status).toBe(200);
    await mongoose.disconnect();
  });
});
