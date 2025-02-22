import 'dotenv/config';
import { createClient } from 'redis';

const REDIS_HOST: string = process.env.REDIS_HOST!;
const REDIS_PORT: number = parseInt(process.env.REDIS_PORT!);
const REDIS_PASSWORD: string = process.env.REDIS_PASSWORD!;
const REDIS_USERNAME: string = process.env.REDIS_USERNAME || '';
if (!REDIS_HOST || !REDIS_PORT) {
    throw new Error('REDIS_HOST or REDIS_PORT is not defined');
}
if (!REDIS_PASSWORD) {
    throw new Error('REDIS_PASSWORD is not defined');
}
const redisUrl = `redis://${REDIS_USERNAME}:${REDIS_PASSWORD}@${REDIS_HOST}:${REDIS_PORT}`;
const redisClient = createClient({
    url: redisUrl
});

redisClient.on('error', (err) => console.error('Redis Client Error', err, 'redisUrl', redisUrl));

export async function initializeRedis() {
  try {
    await redisClient.connect();
    console.log(`Connected to Redis`);
  } catch (err) {
    console.error(`Failed to connect to Redis. Ensure Redis is running.`, err);
    // Optionally exit or handle the error gracefully
  }
}

export default redisClient;