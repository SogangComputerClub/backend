import {
  type Request,
  type Response,
  type NextFunction,
  type RequestHandler,
} from "express";
import bcrypt from "bcryptjs";
import passport from "passport";
import { pool, enforcer } from "../middlewares/db.js";
import type { AuthInfo, User } from "../types/auth.d.ts";
import jwt from "jsonwebtoken";
import {
  REFRESH_TOKEN_SECRET,
  JWT_SECRET,
  EXPIRATION_TIME,
  REFRESH_TOKEN_EXPIRATION_TIME,
} from "../middlewares/auth.js";
import validator from "validator";
import { isDatabaseError } from "../utils/utils.js";

export async function signup(req: Request, res: Response, next: NextFunction) {
  const client = await pool.connect();
  try {
    // request에서 회원가입에 필요한 정보 추출
    const { email, password, username } = req.body;

    const errors = [];

    if (!validator.isEmail(email)) {
      errors.push("Invalid email");
    }

    if (!validator.isLength(password, { min: 8 })) {
      errors.push("Password must be at least 8 characters long");
    }

    if (!validator.isLength(username, { min: 3 })) {
      errors.push("Username must be at least 3 characters long");
    }

    if (errors.length > 0) {
      res.status(400).json({
        message: "Validation failed",
        errors,
      });
    }

    // 비밀번호 해싱
    const hashedPassword = await bcrypt.hash(password, 10);

    // 사용자 정보 삽입 및 생성된 사용자 반환
    const { rows } = await client.query(
      `INSERT INTO users (email, password, username) 
       VALUES ($1, $2, $3) RETURNING *`,
      [email, hashedPassword, username],
    );
    const user = rows[0];

    // 기본 역할 부여 (예: 'user' 역할)
    const { rows: roleRows } = await client.query(
      `SELECT * FROM roles WHERE name = $1`,
      ["user"],
    );
    const userRole = roleRows[0];

    await client.query(
      `INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)`,
      [user.user_id, userRole.role_id],
    );

    if (user.username === "admin") {
      await enforcer.addGroupingPolicy(user.user_id, "admin");
    }
    res.status(201).json({
      message: "User created successfully",
      user: {
        user_id: user.user_id,
        email: user.email,
        username: user.username,
        created_at: user.created_at,
        updated_at: user.updated_at,
      },
    });
  } catch (err) {
    if (isDatabaseError(err) && err.code === "23505") {
      res.status(400).json({ message: "User already exists" });
    } else {
      next(err);
    }
  } finally {
    client.release();
  }
}

export async function login(req: Request, res: Response, next: NextFunction) {
  passport.authenticate(
    "signin",
    { session: false },
    async (
      err: Error | null,
      auth_info: AuthInfo | false | undefined,
      info: { message?: string } | undefined,
    ): Promise<Response | void> => {
      if (err) {
        return next(err);
      }

      if (!auth_info) {
        // 로그인 실패 시 400 응답 전송
        return res
          .status(400)
          .json({ message: info?.message ?? "Login failed" });
      }

      return res.status(200).json({
        message: "Login successful",
        token: {
          accessToken: auth_info.token.accessToken,
          refreshToken: auth_info.token.refreshToken,
        },
      });
    },
  )(req, res, next);
}

export const refreshToken = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  const client = await pool.connect();
  try {
    const refreshToken = req.body.refresh_token;
    const jwtPayload = jwt.verify(refreshToken, REFRESH_TOKEN_SECRET!) as User;
    const { rows } = await client.query(
      "SELECT * FROM users WHERE user_id = $1",
      [jwtPayload.user_id],
    );
    const user = rows[0];
    if (!user) {
      return res.status(401).json({ message: "User not found" });
    }
    // 리프레시 토큰 검증
    const { rows: refreshTokenRows } = await client.query(
      "SELECT * FROM refresh_tokens WHERE user_id = $1 AND token = $2",
      [user.user_id, refreshToken],
    );
    if (refreshTokenRows.length === 0) {
      return res.status(401).json({ message: "Refresh token is not valid" });
    }
    // 액세스 토큰 생성
    const payload: User = {
      user_id: user.user_id,
      email: user.email,
      username: user.username,
    };
    const accessToken = jwt.sign(payload, JWT_SECRET!, {
      expiresIn: EXPIRATION_TIME,
    });
    const newRefreshToken = jwt.sign(payload, REFRESH_TOKEN_SECRET!, {
      expiresIn: REFRESH_TOKEN_EXPIRATION_TIME,
    });

    await client.query(
      "UPDATE refresh_tokens SET token = $1 WHERE user_id = $2 AND token = $3",
      [newRefreshToken, user.user_id, refreshToken],
    );

    return res.status(200).json({
      message: "Access token refreshed",
      token: { accessToken: accessToken, refreshToken: newRefreshToken },
    });
  } catch (err) {
    if (err instanceof jwt.TokenExpiredError) {
      return res.status(401).json({ message: "Refresh token expired" });
    }
    return next(err);
  } finally {
    client.release();
  }
};

export async function logout(req: Request, res: Response, next: NextFunction) {
  passport.authenticate(
    "logout",
    { session: false },
    async (
      err: Error | null,
      success: boolean,
      info: { message?: string } | undefined,
    ) => {
      if (err) {
        return next(err);
      }

      if (!success) {
        return res
          .status(401)
          .json({ message: info?.message ?? "Unauthorized" });
      }

      return res.status(200).json({ message: "Logout successful" });
    },
  )(req, res, next);
}

export const handleToken: RequestHandler = async (req, res, next) => {
  const { grant_type } = req.body;
  if (grant_type === "refresh_token") {
    refreshToken(req, res, next);
  } else {
    res.status(401).json({ message: "Invalid grant type" });
  }
};
