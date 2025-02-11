import 'dotenv/config';
import passport from 'passport';
import { Strategy as JwtStrategy, ExtractJwt, StrategyOptions as JwtStrategyOptions } from 'passport-jwt';
import { Strategy as LocalStrategy } from 'passport-local';
import { pool } from './db';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { AuthInfo, SignupUser } from '../types/auth';
import { StringValue } from 'ms';
import redisClient from './redis';
export const EXPIRATION_TIME: StringValue = (process.env.EXPIRATION_TIME || '1h') as StringValue;
export const REFRESH_TOKEN_SECRET: string | undefined = process.env.REFRESH_TOKEN_SECRET;
export const REFRESH_TOKEN_EXPIRATION_TIME: StringValue = (process.env.REFRESH_TOKEN_EXPIRATION_TIME || '7d') as StringValue;
export const JWT_SECRET: string | undefined = process.env.JWT_SECRET;

if (!JWT_SECRET) {
    throw new Error('JWT_SECRET is not set in the environment');
}

if (!REFRESH_TOKEN_SECRET) {
    throw new Error('REFRESH_TOKEN_SECRET is not set in the environment');
}

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
        // 액세스 토큰 생성 (짧은 만료 시간 사용)
        const accessToken = jwt.sign(
            { user_id: user.user_id, email: user.email },
            JWT_SECRET!,
            { expiresIn: EXPIRATION_TIME }
        );
        // 리프레시 토큰 생성 (긴 만료 시간 사용)
        const refreshToken = jwt.sign(
            { user_id: user.user_id, email: user.email },
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

const refreshOpts: JwtStrategyOptions = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: REFRESH_TOKEN_SECRET!,
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
            // error
            return done(null, false, { message: 'User not found' });
        }

        // 관리자 역할 ID 조회
        const { rows: adminRows } = await client.query('SELECT role_id FROM roles WHERE name = $1', ['admin']);
        const adminRoleId = adminRows[0]?.role_id;
        
        // 사용자에게 부여된 모든 역할 조회
        const { rows: userRoleRows } = await client.query('SELECT role_id FROM user_roles WHERE user_id = $1', [user.user_id]);
        // 역할 배열에 adminRoleId가 포함되어 있는지 체크
        user.is_admin = userRoleRows.some(r => r.role_id === adminRoleId);

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
        const user = rows[0];
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

        return done(null, true, { message: 'Logout successful' });
    } catch (err) {
        console.error(err);
        return done(null, false, { message: `Error: ${err}` });
    } finally {
        client.release();
    }
}));

// refresh token strategy
passport.use('refresh_access_token', new JwtStrategy(refreshOpts, async (req, jwtPayload, done) => {
    const client = await pool.connect();
    try {
        console.log(`refresh_access_token jwtPayload: ${JSON.stringify(jwtPayload)}`);
        const refreshToken = req.headers.authorization?.split(' ')[1];
        const { rows } = await client.query('SELECT * FROM users WHERE user_id = $1', [jwtPayload.user_id]);
        const user = rows[0];
        if (!user) {
            return done(null, false);
        }
        // 리프레시 토큰 검증
        const { rows: refreshTokenRows } = await client.query('SELECT * FROM refresh_tokens WHERE user_id = $1 AND token = $2', [user.user_id, refreshToken]);
        if (!refreshTokenRows[0]) {
            return done(null, false);
        }
        // 액세스 토큰 생성
        const payload: SignupUser = {
            user_id: user.user_id,
            email: user.email,
            username: user.username,
            is_admin: user.is_admin,
        };
        const accessToken = jwt.sign(
            payload,
            JWT_SECRET!,
            { expiresIn: EXPIRATION_TIME }
        );
        return done(null, accessToken);
    } catch (err) {
        console.error(err);
        return done(err);
    } finally {
        client.release();
    }
}));

// refresh token strategy
passport.use('refresh_refresh_token', new JwtStrategy(opts, async (req, jwtPayload, done) => {
    const client = await pool.connect();
    try {
        console.log(`refresh_refresh_token jwtPayload: ${JSON.stringify(jwtPayload)}`);
        // 사용자 조회
        const accessToken = req.headers.authorization?.split(' ')[1];
        const refreshToken = req.body.refresh_token;
        if (await redisClient.get(accessToken)) {
            return done(null, false, { message: 'Access token is blacklisted' });
        }
        const { rows } = await client.query('SELECT * FROM users WHERE user_id = $1', [jwtPayload.user_id]);
        const user = rows[0];
        if (!user) {
            return done(null, false, { message: 'User not found' });
        }

        if (!refreshToken) {
            return done(null, false, { message: 'Refresh token is not provided' });
        }

        // DB에서 기존 리프레시 토큰 검증
        const { rows: refreshTokenRows } = await client.query(
            'SELECT * FROM refresh_tokens WHERE user_id = $1 AND token = $2',
            [user.user_id, refreshToken]
        );
        if (refreshTokenRows.length === 0) {
            return done(null, false, { message: 'Refresh token is not valid' });
        }

        // 기존 리프레시 토큰 삭제 (회전 토큰 전략)
        await client.query(
            'DELETE FROM refresh_tokens WHERE user_id = $1 AND token = $2',
            [user.user_id, refreshToken]
        );

        const payload: SignupUser = {
            user_id: user.user_id,
            email: user.email,
            username: user.username,
            is_admin: user.is_admin,
        };

        // 새 리프레시 토큰 생성
        const newRefreshToken = jwt.sign(
            payload,
            REFRESH_TOKEN_SECRET!,
            { expiresIn: REFRESH_TOKEN_EXPIRATION_TIME }
        );

        // 기존 리프레시 토큰을 새 리프레시 토큰으로 교체
        await client.query(
            'INSERT INTO refresh_tokens (user_id, token) VALUES ($1, $2)',
            [user.user_id, newRefreshToken]
        );

        return done(null, { accessToken: accessToken, refreshToken: newRefreshToken });
    } catch (err) {
        console.error(err);
        return done(err, false, { message: `Error: ${err}` });
    } finally {
        client.release();
    }
}));

export const initializeAuth = () => passport.initialize();

export { passport };
