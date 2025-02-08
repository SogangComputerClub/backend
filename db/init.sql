CREATE TABLE IF NOT EXISTS books (
  book_id SERIAL PRIMARY KEY,
  title VARCHAR(255) NOT NULL,
  author VARCHAR(255) NOT NULL,
  is_available BOOLEAN NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    user_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS roles (
  role_id SERIAL PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
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
  name VARCHAR(255) NOT NULL,
  description TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS role_permissions (
  role_id INTEGER REFERENCES roles(role_id) ON DELETE CASCADE,
  permission_id INTEGER REFERENCES permissions(permission_id) ON DELETE CASCADE,
  PRIMARY KEY (role_id, permission_id)
);

CREATE VIEW IF NOT EXISTS user_permissions AS
SELECT
  user_id,
  array_agg(permission_id) AS permissions
FROM
  user_roles
  JOIN role_permissions ON user_roles.role_id = role_permissions.role_id
GROUP BY
  user_id;

CREATE TABLE refresh_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(user_id),
    token TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    revoked BOOLEAN DEFAULT FALSE
);

INSERT INTO roles (name, description) VALUES
('admin', 'Administrator role with all permissions'),
('user', 'Standard user role with limited permissions');

INSERT INTO permissions (name, description) VALUES
('create_book', 'Ability to create new books'),
('edit_book', 'Ability to edit existing books'),
('delete_book', 'Ability to delete books'),
('view_books', 'Ability to view all books');

INSERT INTO role_permissions (role_id, permission_id) VALUES
(1, 1),
(1, 2),
(1, 3),
(1, 4),
(2, 4);
