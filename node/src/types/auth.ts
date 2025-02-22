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

export type AuthStrategy = 'jwt' | 'signin' | 'logout'

export interface CheckAclOptions {
  permission?: string;
  strategy: AuthStrategy;
  passportOptions?: {
    session?: boolean;
    failWithError?: boolean;
    failureMessage?: boolean;
    failureFlash?: boolean;
  };
}