import { Pool } from 'pg';
import 'dotenv/config';
import { Client } from 'pg';
// Database connection
export const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
});
  
pool.connect((err, client, release) => {
    if (err) {
        console.error('Error acquiring client', err.stack);
    } else {
        console.log('Connected to the database');
    }
    release();
});

export const client = new Client({
    host: process.env.DB_HOST!,
    port: parseInt(process.env.DB_PORT!),
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    ssl: process.env.NODE_ENV === 'production' ? true : false,
});