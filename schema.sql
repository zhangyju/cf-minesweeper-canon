-- cf-minesweeper D1 数据库架构
-- 游戏核心功能的数据库设计

-- 1. 排行榜表 - 替代 leaderboard:{difficulty} KV 键
CREATE TABLE IF NOT EXISTS leaderboards (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    difficulty TEXT NOT NULL CHECK (difficulty IN ('beginner', 'intermediate', 'expert')),
    time INTEGER NOT NULL,
    timestamp TEXT NOT NULL,
    game_id TEXT NOT NULL UNIQUE,
    moves INTEGER NOT NULL,
    verified BOOLEAN DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(username, difficulty)
);

-- 2. 用户统计表 - 替代 security:user_stats:{username}:{difficulty} KV 键
CREATE TABLE IF NOT EXISTS user_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    difficulty TEXT NOT NULL CHECK (difficulty IN ('beginner', 'intermediate', 'expert')),
    submissions INTEGER DEFAULT 0,
    best_time INTEGER,
    average_time REAL DEFAULT 0,
    total_time INTEGER DEFAULT 0,
    last_submission TEXT,
    suspicious_count INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(username, difficulty)
);



-- 4. 速率限制表 - 替代各种速率限制 KV 键
CREATE TABLE IF NOT EXISTS rate_limits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_type TEXT NOT NULL, -- 'ip', 'fingerprint', etc.
    key_value TEXT NOT NULL,
    count INTEGER DEFAULT 0,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(key_type, key_value)
);

-- 性能优化索引
-- 排行榜查询优化：按难度和时间排序
CREATE INDEX IF NOT EXISTS idx_leaderboards_difficulty_time ON leaderboards(difficulty, time);

-- 用户统计查询优化：按用户名和难度查找
CREATE INDEX IF NOT EXISTS idx_user_stats_username_difficulty ON user_stats(username, difficulty);

-- 速率限制查询优化：按类型、值和过期时间
CREATE INDEX IF NOT EXISTS idx_rate_limits_key_expires ON rate_limits(key_type, key_value, expires_at);



-- 额外的性能优化索引
-- 排行榜按用户名查找（用于检查用户是否已有记录）
CREATE INDEX IF NOT EXISTS idx_leaderboards_username ON leaderboards(username);

-- 用户统计按更新时间排序（用于清理过期数据）
CREATE INDEX IF NOT EXISTS idx_user_stats_updated_at ON user_stats(updated_at);

-- 速率限制按过期时间排序（用于自动清理）
CREATE INDEX IF NOT EXISTS idx_rate_limits_expires_at ON rate_limits(expires_at);
