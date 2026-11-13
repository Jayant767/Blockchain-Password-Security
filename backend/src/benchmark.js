import { performance } from 'node:perf_hooks';
import { hashPassword } from './security.js';
const samples = Math.max(1, Math.min(20, Number(process.env.ARGON2_BENCH_SAMPLES || 5)));
const timings = [];
for (let i=0; i<samples; i++) {
  const started = performance.now();
  await hashPassword(`benchmark-only-random-input-${i}-${process.pid}`);
  timings.push(performance.now()-started);
}
timings.sort((a,b)=>a-b);
const median = timings[Math.floor(timings.length/2)];
console.log(JSON.stringify({algorithm:'Argon2id',samples,memoryKiB:process.env.ARGON2_MEMORY_KIB||19456,timeCost:process.env.ARGON2_TIME_COST||2,parallelism:process.env.ARGON2_PARALLELISM||1,medianMs:Number(median.toFixed(2))},null,2));
