PRAGMA foreign_keys=ON;
CREATE TABLE companies(id TEXT PRIMARY KEY,name TEXT NOT NULL,company_code TEXT NOT NULL UNIQUE,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE users(id TEXT PRIMARY KEY,email TEXT NOT NULL UNIQUE,username TEXT NOT NULL UNIQUE,name TEXT NOT NULL,password_hash TEXT NOT NULL,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE memberships(id TEXT PRIMARY KEY,company_id TEXT NOT NULL REFERENCES companies(id),user_id TEXT NOT NULL REFERENCES users(id),role TEXT NOT NULL CHECK(role IN ('owner','manager','member')),created_at TEXT DEFAULT CURRENT_TIMESTAMP,UNIQUE(company_id,user_id));
CREATE TABLE records(id TEXT PRIMARY KEY,company_id TEXT NOT NULL REFERENCES companies(id),user_id TEXT NOT NULL REFERENCES users(id),kind TEXT NOT NULL,payload TEXT NOT NULL,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE documents(id TEXT PRIMARY KEY,company_id TEXT NOT NULL REFERENCES companies(id),user_id TEXT NOT NULL REFERENCES users(id),name TEXT NOT NULL,object_key TEXT NOT NULL,mime TEXT NOT NULL,size INTEGER NOT NULL,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE INDEX idx_members_company ON memberships(company_id); CREATE INDEX idx_records_company ON records(company_id); CREATE INDEX idx_docs_company ON documents(company_id);
