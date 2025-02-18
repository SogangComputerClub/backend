export interface User {
  user_id: string;
  email: string;
  username: string;
}

export interface AuthInfo {
  user: User;
  token: {
    accessToken: string;
    refreshToken: string;
  }
}

export type authStrategy = 'jwt' | 'signin' | 'logout'