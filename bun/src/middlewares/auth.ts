import 'dotenv/config';
import passport from 'passport';
import { Strategy as JwtStrategy, ExtractJwt, type StrategyOptions as JwtStrategyOptions } from 'passport-jwt';
import { Strategy as LocalStrategy } from 'passport-local';
import { pool, client } from './db';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import type { AuthInfo, User } from '../types/auth';
import type { StringValue } from 'ms';
import redisClient from './redis';
import { newEnforcer } from 'casbin';
import { BasicAdapter } from 'casbin-basic-adapter';
import type { NextFunction, Request, Response } from 'express';

export const EXPIRATION_TIME: StringValue = (process.env.EXPIRATION_TIME || '1h') as StringValue;
export const REFRESH_TOKEN_SECRET: string | undefined = process.env.REFRESH_TOKEN_SECRET;
export const REFRESH_TOKEN_EXPIRATION_TIME: StringValue = (process.env.REFRESH_TOKEN_EXPIRATION_TIME || '7d') as StringValue;
export const JWT_SECRET: string | undefined = process.env.JWT_SECRET;
const ENFORCER_MODEL_PATH: string | undefined = process.env.ENFORCER_MODEL_PATH || 'src/config/casbin_model.conf';
const ENFORCER_POLICY_TABLE_NAME: string | undefined = process.env.ENFORCER_POLICY_TABLE_NAME || 'role_permissions';

if (!JWT_SECRET) {
    throw new Error('JWT_SECRET is not set in the environment');
}

if (!REFRESH_TOKEN_SECRET) {
    throw new Error('REFRESH_TOKEN_SECRET is not set in the environment');
}

const policy = await BasicAdapter.newAdapter('pg', client, ENFORCER_POLICY_TABLE_NAME);

const enforcer = await newEnforcer(ENFORCER_MODEL_PATH, policy);


passport.use('signin', new LocalStrategy({
  usernameField: 'email',
  passwordField: 'password',
}, async (email, password, done) => {
    const client = await pool.connect();
    try {
        const { rows } = await client.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = rows[0];
        if (!user) {
            return done(null, false, { message: 'User not found' });
        }
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) {
            return done(null, false, { message: 'Incorrect password' });
        }
        const payload: User = {
            user_id: user.user_id,
            email: user.email,
            username: user.username
        }
        // 액세스 토큰 생성 (짧은 만료 시간 사용)
        const accessToken = jwt.sign(
            payload,
            JWT_SECRET!,
            { expiresIn: EXPIRATION_TIME }
        );
        // 리프레시 토큰 생성 (긴 만료 시간 사용)
        const refreshToken = jwt.sign(
            payload,
            REFRESH_TOKEN_SECRET!,
            { expiresIn: REFRESH_TOKEN_EXPIRATION_TIME }
        );

        // 리프레시 토큰을 데이터베이스에 저장
        await client.query(
            'INSERT INTO refresh_tokens (user_id, token) VALUES ($1, $2)',
            [user.user_id, refreshToken]
        );

        const respoonse: AuthInfo = {
            user: user,
            token: { accessToken, refreshToken }
        }
        return done(null, respoonse);
    } catch (err) {
        console.error(err);
        return done(err);
    } finally {
        client.release();
    }
}));

/**
 * JWT strategy options configuration.
 *
 * @remarks
 * This configuration object specifies how to extract and verify JWTs from incoming requests.
 *
 * @property jwtFromRequest - A function that extracts the JWT from the request header, using the Bearer token scheme.
 * @property secretOrKey - The secret key used for verifying the integrity and authenticity of the JWT.
 */
const opts: JwtStrategyOptions = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: JWT_SECRET!,
    passReqToCallback: true,
};

passport.use("jwt", new JwtStrategy(opts, async (req, jwtPayload, done) => {
    const client = await pool.connect();
    try {
        const accessToken = req.headers.authorization?.split(' ')[1];
        if (await redisClient.get(accessToken)) {
            return done(null, false, { message: 'Access token is blacklisted' });
        }
        const { rows } = await client.query('SELECT * FROM users WHERE user_id = $1', [jwtPayload.user_id]);
        const user = rows[0];
        if (!user) {
            return done(null, false, { message: 'User not found' });
        }

        return done(null, user);
    } catch (err) {
        console.error(err);
        return done(null, false, { message: `Error: ${err}` });
    } finally {
        client.release();
    }
}));

passport.use('logout', new JwtStrategy(opts, async (req, jwtPayload, done) => {
    const client = await pool.connect();
    try {
        const accessToken = req.headers.authorization?.split(' ')[1];
        if (await redisClient.get(accessToken)) {
            return done(null, false, { message: 'Access token is blacklisted' });
        }
        const { rows } = await client.query('SELECT * FROM users WHERE user_id = $1', [jwtPayload.user_id]);
        const user: User = rows[0];
        if (!user) {
            return done(null, false, { message: 'User not found' });
        }

        // delete current refresh token from postgresql
        await client.query('DELETE FROM refresh_tokens WHERE user_id = $1', [user.user_id]);

        // add current access token to blacklisted access tokens
        await redisClient.set(
            accessToken,
            'true',
            { EX: 60 * 60 * 24 }
        );

        return done(null, false, { message: 'Logout successful' });
    } catch (err) {
        console.error(err);
        return done(null, false, { message: `Error: ${err}` });
    } finally {
        client.release();
    }
}));

// first authenticate with jwt, then check acl
const checkAcl = (permission: string, strategy: string) => {
    return (req: Request, res: Response, next: NextFunction) => {
        passport.authenticate(strategy, { session: false }, async (err: any, user?: User | false, info?: any) => {
            if (err) {
                return next(err);
            }
            if (!user) {
                return res.status(401).json(info || { message: 'Unauthorized' });
            }
            const allowed = await enforcer.hasPermissionForUser(user.user_id, permission);
            if (!allowed) {
                return res.status(403).json({ message: 'Forbidden' });
            }
            return next();
        })(req, res, next);
    }
}

const initializeAuth = () => passport.initialize();

export { passport, initializeAuth, checkAcl };
