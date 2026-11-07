-- Database per service + user MySQL per service (least privilege).
-- Password di bawah hanya untuk DEV. Ganti di produksi (dan sesuaikan docker-compose.yml).

CREATE DATABASE IF NOT EXISTS auth_db    CHARACTER SET utf8mb4;
CREATE DATABASE IF NOT EXISTS order_db   CHARACTER SET utf8mb4;
CREATE DATABASE IF NOT EXISTS invoice_db CHARACTER SET utf8mb4;
CREATE DATABASE IF NOT EXISTS policy_db  CHARACTER SET utf8mb4;

CREATE USER IF NOT EXISTS 'auth_svc'@'%'    IDENTIFIED BY 'auth_dev_pw';
CREATE USER IF NOT EXISTS 'order_svc'@'%'   IDENTIFIED BY 'order_dev_pw';
CREATE USER IF NOT EXISTS 'invoice_svc'@'%' IDENTIFIED BY 'invoice_dev_pw';
CREATE USER IF NOT EXISTS 'policy_svc'@'%'  IDENTIFIED BY 'policy_dev_pw';

GRANT SELECT, INSERT, UPDATE, DELETE ON auth_db.*    TO 'auth_svc'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON order_db.*   TO 'order_svc'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON invoice_db.* TO 'invoice_svc'@'%';
GRANT SELECT, INSERT                 ON policy_db.*  TO 'policy_svc'@'%';

-- ============ auth_db ============
USE auth_db;
CREATE TABLE users (
  id            CHAR(36)     NOT NULL PRIMARY KEY,          -- UUID v4 (anti-IDOR)
  email         VARCHAR(190) NOT NULL UNIQUE,
  password_hash VARCHAR(100) NOT NULL,
  role          ENUM('user','admin') NOT NULL DEFAULT 'user',
  created_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE refresh_tokens (
  id         CHAR(36)     NOT NULL PRIMARY KEY,
  user_id    CHAR(36)     NOT NULL,
  token_hash CHAR(64)     NOT NULL UNIQUE,                  -- hanya hash yang disimpan
  scope      VARCHAR(255) NOT NULL,
  expires_at DATETIME     NOT NULL,
  revoked    TINYINT(1)   NOT NULL DEFAULT 0,
  created_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_rt_user (user_id),
  CONSTRAINT fk_rt_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ============ order_db ============
USE order_db;
CREATE TABLE orders (
  id           CHAR(36)      NOT NULL PRIMARY KEY,
  owner_id     CHAR(36)      NOT NULL,
  status       ENUM('pending','invoiced') NOT NULL DEFAULT 'pending',
  total_amount DECIMAL(14,2) NOT NULL,
  created_at   TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at   TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_orders_owner (owner_id, created_at)
) ENGINE=InnoDB;

CREATE TABLE order_items (
  id           CHAR(36)      NOT NULL PRIMARY KEY,
  order_id     CHAR(36)      NOT NULL,
  product_name VARCHAR(120)  NOT NULL,
  quantity     INT UNSIGNED  NOT NULL,
  unit_price   DECIMAL(14,2) NOT NULL,
  INDEX idx_items_order (order_id),
  CONSTRAINT fk_items_order FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ============ invoice_db ============
USE invoice_db;
CREATE TABLE invoices (
  id          CHAR(36)      NOT NULL PRIMARY KEY,
  order_id    CHAR(36)      NOT NULL UNIQUE,                -- 1 order = 1 invoice
  owner_id    CHAR(36)      NOT NULL,
  amount      DECIMAL(14,2) NOT NULL,
  status      ENUM('issued','paid','void') NOT NULL DEFAULT 'issued',
  description VARCHAR(255)  NULL,
  paid_at     DATETIME      NULL,
  created_at  TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at  TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_inv_owner (owner_id, created_at),
  INDEX idx_inv_status (status)
) ENGINE=InnoDB;

-- ============ policy_db ============
USE policy_db;
CREATE TABLE decision_logs (
  id            CHAR(36)    NOT NULL PRIMARY KEY,
  request_id    VARCHAR(64) NULL,
  service       VARCHAR(32) NULL,
  subject_id    CHAR(36)    NOT NULL,
  role          VARCHAR(16) NOT NULL,
  action        VARCHAR(64) NOT NULL,
  resource_type VARCHAR(32) NULL,
  resource_id   CHAR(36)    NULL,
  effect        ENUM('allow','deny') NOT NULL,
  code          VARCHAR(32) NULL,
  reason        VARCHAR(255) NULL,
  created_at    TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_dl_subject (subject_id, created_at),
  INDEX idx_dl_effect (effect, created_at)
) ENGINE=InnoDB;
