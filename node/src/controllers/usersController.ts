import { Request, Response, NextFunction } from 'express';
import bcrypt from 'bcryptjs';
import passport from 'passport';
import jwt from 'jsonwebtoken';
import { pool } from '../middlewares/db'; // 기존 db 파일 경로에 맞게 조정하세요

// 타입 정의 예시 (실제 프로젝트에 맞게 수정하세요)
interface SignupUser {
  user_id: number;
  email: string;
  username: string;
  // 필요한 기타 필드 추가
}

interface User {
  user_id: number;
  email: string;
  username: string;
}

export async function signup(req: Request, res: Response, next: NextFunction) {
  const client = await pool.connect();
  try {
    // request에서 회원가입에 필요한 정보 추출
    const { email, password, username } = req.body;
    
    // 비밀번호 해싱
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // 사용자 정보 삽입 및 생성된 사용자 반환
    const { rows } = await client.query(
      `INSERT INTO users (email, password, username) 
       VALUES ($1, $2, $3) RETURNING *`,
      [email, hashedPassword, username]
    );
    const user = rows[0];

    // 기본 역할 부여 (예: 'user' 역할)
    const { rows: roleRows } = await client.query(
      `SELECT * FROM roles WHERE name = $1`,
      ['user']
    );
    const userRole = roleRows[0];

    await client.query(
      `INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)`,
      [user.user_id, userRole.role_id]
    );

    res.status(201).json(user);
  } catch (err) {
    next(err);
  } finally {
    client.release();
  }
}

export async function login(req: Request, res: Response, next: NextFunction) {
  passport.authenticate(
    'signin',
    { session: false },
    async (
      err: Error | null,
      user: SignupUser | false | undefined,
      info: { message?: string } | undefined
    ): Promise<any> => {
      if (err) {
        return next(err);
      }
      if (!user) {
        // 로그인 실패 시 400 응답 전송
        return res.status(400).json({ message: info?.message || 'Login failed' });
      }

      try {
        // JWT 페이로드 준비 (DB 스키마에 맞게 프로퍼티 이름 확인)
        const payload: User = {
          user_id: user.user_id,
          email: user.email,
          username: user.username
        };

        // JWT 토큰 생성 (비밀키가 process.env에 정의되어 있어야 함)
        const accessToken = jwt.sign(payload, process.env.JWT_SECRET as string, { expiresIn: '1h' });
        const refreshToken = jwt.sign(payload, process.env.REFRESH_TOKEN_SECRET as string, { expiresIn: '7d' });

        // 토큰과 함께 성공 응답 전송
        return res.status(200).json({ message: 'Login successful', token: { accessToken, refreshToken } });
      } catch (error) {
        return next(error);
      }
    }
  )(req, res, next);
}