export interface User {
  user_id: number;
  email: string;
  username: string;
}

export interface SignupUser extends User {
  is_admin: boolean;
}

export interface AuthInfo {
  message?: string;
} 