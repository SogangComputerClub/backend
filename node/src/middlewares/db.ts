import pg from 'pg';
import { newEnforcer } from 'casbin';
import { SequelizeAdapter } from 'casbin-sequelize-adapter';

export const pool = new pg.Pool({
    connectionString: process.env.DATABASE_URL,
});
const ENFORCER_MODEL_PATH: string | undefined = process.env.ENFORCER_MODEL_PATH || 'src/config/casbin_model.conf';
const ENFORCER_POLICY_TABLE_NAME: string | undefined = process.env.ENFORCER_POLICY_TABLE_NAME || 'casbin_rule';

pool.connect((err: Error | undefined, client: any, release: () => void) => {
    if (err) {
        console.error('Error acquiring client', err.stack);
    } else {
        console.log('Connected to the database');
    }
    release();
});


const policy = await SequelizeAdapter.newAdapter({
    username: process.env.DB_USER,
    password: process.env.DB_PASSWORD?.toString(),
    database: process.env.DB_NAME,
    dialect: 'postgres'
},
true);

export const enforcer = await newEnforcer(ENFORCER_MODEL_PATH, policy);