import "dotenv/config";
import pg, { PoolClient } from "pg";
import { newEnforcer } from "casbin";
import { SequelizeAdapter } from "casbin-sequelize-adapter";
import { __dirname } from "../utils/utils.js";
import path from "path";

const policy = await SequelizeAdapter.newAdapter(
  {
    username: process.env.POSTGRES_USER,
    password: process.env.POSTGRES_PASSWORD,
    database: process.env.POSTGRES_DB,
    dialect: "postgres",
    host: process.env.POSTGRES_HOST ?? "localhost",
  },
  true,
);

export const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
});

const ENFORCER_MODEL_PATH: string | undefined =
  process.env.ENFORCER_MODEL_PATH ??
  path.join(__dirname, "config", "casbin_model.conf");

pool.connect(
  (
    err: Error | undefined,
    client: PoolClient | undefined,
    release: () => void,
  ) => {
    if (err) {
      console.error("Error acquiring client", err.stack);
    } else {
      console.log("Connected to the database");
    }
    release();
  },
);

const enforcer = await newEnforcer(ENFORCER_MODEL_PATH, policy);

export { enforcer };
