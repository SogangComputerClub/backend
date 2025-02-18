CREATE TABLE IF NOT EXISTS books (
  book_id SERIAL PRIMARY KEY,
  title TEXT NOT NULL,
  author TEXT NOT NULL,
  is_available BOOLEAN NOT NULL
);

CREATE DOMAIN EMAIL AS TEXT CHECK (
  VALUE ~* '^((?:[A-Za-z0-9!#$%&''*+\-\/=?^_`{|}~]|(?<=^|\.)"|"(?=$|\.|@)|(?<=".*)[ .](?=.*")|(?<!\.)\.){1,64})(@)((?:[A-Za-z0-9.\-])*(?:[A-Za-z0-9])\.(?:[A-Za-z0-9]){2,})$'
);

CREATE TABLE IF NOT EXISTS users (
    user_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email EMAIL UNIQUE NOT NULL,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS roles (
  role_id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_roles (
  user_id UUID REFERENCES users(user_id) ON DELETE CASCADE,
  role_id INTEGER REFERENCES roles(role_id) ON DELETE CASCADE,
  PRIMARY KEY (user_id, role_id)
);

CREATE TABLE IF NOT EXISTS permissions (
  permission_id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS role_permissions (
  role_id INTEGER REFERENCES roles(role_id) ON DELETE CASCADE,
  permission_id INTEGER REFERENCES permissions(permission_id) ON DELETE CASCADE,
  PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id SERIAL PRIMARY KEY,
    user_id UUID REFERENCES users(user_id) ON DELETE CASCADE,
    token TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    revoked BOOLEAN DEFAULT FALSE
);

INSERT INTO users (user_id, email, username, password) VALUES
('dfb0a0d3-6a21-4631-ac90-3f5419442eed', 'admin@admin.com', 'admin', 'password');

INSERT INTO roles (name, description) VALUES
('admin', 'Administrator role with all permissions'),
('user', 'Standard user role with limited permissions');

INSERT INTO permissions (name, description) VALUES
('create_book', 'Ability to create new books'),
('edit_book', 'Ability to edit existing books'),
('delete_book', 'Ability to delete books'),
('view_books', 'Ability to view all books'),
('acl_hello', 'Ability to access the hello route');

CREATE TABLE IF NOT EXISTS casbin_rule (
  id SERIAL PRIMARY KEY,
  ptype TEXT,
  v0 TEXT,
  v1 TEXT,
  v2 TEXT,
  v3 TEXT,
  v4 TEXT,
  v5 TEXT,
  v6 TEXT
);

INSERT INTO casbin_rule (ptype, v0, v1, v2) VALUES
('p', 'admin', 'create_book', 'allow'),
('p', 'admin', 'edit_book', 'allow'),
('p', 'admin', 'delete_book', 'allow'),
('p', 'admin', 'view_books', 'allow'),
('p', 'admin', 'acl_hello', 'allow'),
('p', 'user', 'view_books', 'allow'),
('g', 'admin', 'user', NULL);