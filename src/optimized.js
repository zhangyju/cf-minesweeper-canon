// 🎮 扫雷游戏 - Cloudflare pages 版本
// 经典扫雷游戏，支持多难度级别和在线排行榜

// 数据验证工具类
class DataValidator {
  // 用户名验证 - 增强安全性
  static validateUsername(username) {
    // 基础类型检查
    if (!username || typeof username !== 'string') {
      return { valid: false, reason: '用户名格式无效' };
    }

    // 长度限制检查（防止DoS攻击）
    if (username.length > 100) {
      return { valid: false, reason: '输入过长' };
    }

    const trimmed = username.trim();

    // 空值检查
    if (trimmed.length === 0) {
      return { valid: false, reason: '用户名不能为空' };
    }

    // 最小长度检查
    if (trimmed.length < 1) {
      return { valid: false, reason: '用户名过短' };
    }

    // 检查长度（支持Unicode字符）
    const length = [...trimmed].length;
    if (length > 16) {
      return { valid: false, reason: '用户名过长' };
    }

    // 防止纯空格用户名
    if (/^\s+$/.test(trimmed)) {
      return { valid: false, reason: '用户名无效' };
    }

    // 字符白名单：字母、数字、中文、下划线、连字符（移除空格支持）
    const allowedPattern = /^[a-zA-Z0-9\u4e00-\u9fa5_\-]+$/;
    if (!allowedPattern.test(trimmed)) {
      return { valid: false, reason: '用户名包含无效字符' };
    }

    // 防止纯特殊字符
    if (/^[_\-]+$/.test(trimmed)) {
      return { valid: false, reason: '用户名格式无效' };
    }

    // 防止HTML标签和脚本注入
    if (/<[^>]*>/.test(trimmed) || /javascript:/i.test(trimmed) || /on\w+=/i.test(trimmed)) {
      return { valid: false, reason: '用户名包含无效内容' };
    }

    // 防止SQL注入关键字
    const sqlKeywords = /\b(select|insert|update|delete|drop|union|script|alert)\b/i;
    if (sqlKeywords.test(trimmed)) {
      return { valid: false, reason: '用户名包含保留字符' };
    }

    // 输入清理：移除潜在的危险字符
    const cleaned = trimmed.replace(/[<>'"&]/g, '');
    if (cleaned !== trimmed) {
      return { valid: false, reason: '用户名包含特殊字符' };
    }

    return { valid: true, value: trimmed };
  }

  // 时间验证 - 增强边界检查
  static validateTime(time) {
    // 基础类型检查
    if (typeof time !== 'number' && typeof time !== 'string') {
      return { valid: false, reason: '时间格式无效' };
    }

    // 字符串长度限制（防止DoS攻击）
    if (typeof time === 'string' && time.length > 20) {
      return { valid: false, reason: '输入过长' };
    }

    const numTime = Number(time);

    // 数值有效性检查
    if (isNaN(numTime) || !isFinite(numTime)) {
      return { valid: false, reason: '时间数值无效' };
    }

    // 范围检查 - 更严格的边界
    if (numTime < 0.1) {
      return { valid: false, reason: '时间过短' };
    }

    if (numTime > 99999) {
      return { valid: false, reason: '时间过长' };
    }

    // 精度检查 - 防止过度精确的浮点数
    const decimalPlaces = (numTime.toString().split('.')[1] || '').length;
    if (decimalPlaces > 3) {
      return { valid: false, reason: '时间精度过高' };
    }

    // 合理性检查 - 防止异常值
    if (numTime < 0.1 || numTime > 9999) {
      return { valid: false, reason: '时间超出合理范围' };
    }

    return { valid: true, value: parseFloat(numTime.toFixed(3)) };
  }

  // 难度验证 - 增强类型和格式检查
  static validateDifficulty(difficulty) {
    // 基础类型检查
    if (!difficulty || typeof difficulty !== 'string') {
      return { valid: false, reason: '难度格式无效' };
    }

    // 长度限制检查
    if (difficulty.length > 50) {
      return { valid: false, reason: '输入过长' };
    }

    // 清理输入
    const cleaned = difficulty.trim().toLowerCase();

    // 白名单验证
    const validDifficulties = ['beginner', 'intermediate', 'expert'];
    if (!validDifficulties.includes(cleaned)) {
      return { valid: false, reason: '难度级别无效' };
    }

    return { valid: true, value: cleaned };
  }

  // 游戏数据结构验证 - 增强安全检查
  static validateGameDataStructure(gameData) {
    // 基础类型检查
    if (!gameData || typeof gameData !== 'object' || Array.isArray(gameData)) {
      return { valid: false, reason: '游戏数据格式错误' };
    }

    // 防止过大的对象（DoS攻击防护）
    const jsonString = JSON.stringify(gameData);
    if (jsonString.length > 10000) {
      return { valid: false, reason: '游戏数据过大' };
    }

    // 必需字段检查
    const requiredFields = [
      'difficulty', 'time', 'moves', 'gameId', 'timestamp',
      'boardSize', 'mineCount', 'gameEndTime', 'firstClickTime', 'gameState'
    ];

    for (const field of requiredFields) {
      if (!(field in gameData)) {
        return { valid: false, reason: '游戏数据不完整' };
      }
    }

    // 字段类型验证
    if (typeof gameData.gameId !== 'string' || gameData.gameId.length > 100) {
      return { valid: false, reason: '游戏ID格式错误' };
    }

    if (typeof gameData.gameState !== 'string' || !['won', 'lost', 'playing'].includes(gameData.gameState)) {
      return { valid: false, reason: '游戏状态无效' };
    }

    // 数值字段验证
    const numericFields = ['time', 'moves', 'mineCount', 'gameEndTime', 'firstClickTime'];
    for (const field of numericFields) {
      if (typeof gameData[field] !== 'number' || !isFinite(gameData[field])) {
        return { valid: false, reason: '游戏数据包含无效数值' };
      }
    }

    // 棋盘尺寸验证
    if (!gameData.boardSize || typeof gameData.boardSize !== 'object') {
      return { valid: false, reason: '棋盘尺寸数据无效' };
    }

    if (typeof gameData.boardSize.width !== 'number' || typeof gameData.boardSize.height !== 'number') {
      return { valid: false, reason: '棋盘尺寸格式错误' };
    }

    return { valid: true, value: gameData };
  }
}

// 简化的验证函数（保持向后兼容）
const validateUsername = (username) => DataValidator.validateUsername(username).valid;
const validateTime = (time) => DataValidator.validateTime(time).valid;

// KVStorageManager 已移除 - 完全迁移到 D1StorageManager

// D1存储管理器 - 完全替代 KV 存储，提供更强大的数据管理能力
class D1StorageManager {
  constructor(env, useCache = true) {
    this.db = env.DB; // D1 数据库绑定
    this.useCache = useCache;
    this.cache = globalCache;
  }

  // 生成缓存键（保持与 KV 兼容的格式）
  static createCacheKey(prefix, ...parts) {
    return `${prefix}:${parts.join(':')}`;
  }

  // ⚡ 排行榜操作：获取排行榜数据
  async getLeaderboard(difficulty, limit = 20) {
    return await ErrorHandler.handleAsyncError(async () => {
      const cacheKey = D1StorageManager.createCacheKey('leaderboard', difficulty);

      // 尝试从缓存获取
      if (this.useCache) {
        const cached = this.cache.get(cacheKey);
        if (cached !== null) {
          return cached;
        }
      }

      // 从 D1 数据库查询排行榜
      const { results } = await this.db.prepare(
        'SELECT username, time, timestamp, game_id, moves, verified FROM leaderboards WHERE difficulty = ? ORDER BY time ASC LIMIT ?'
      ).bind(difficulty, limit).all();

      // 存入缓存
      if (this.useCache) {
        this.cache.set(cacheKey, results, 30000); // 30秒缓存
      }

      return results;
    }, `D1StorageManager.getLeaderboard(${difficulty})`, []);
  }

  // ⚡ 排行榜操作：保存排行榜记录
  async saveLeaderboardRecord(record) {
    return await ErrorHandler.handleAsyncError(async () => {
      const { username, difficulty, time, timestamp, gameId, moves, verified = true } = record;

      // 使用 INSERT OR REPLACE 确保数据一致性
      await this.db.prepare(
        'INSERT OR REPLACE INTO leaderboards (username, difficulty, time, timestamp, game_id, moves, verified) VALUES (?, ?, ?, ?, ?, ?, ?)'
      ).bind(username, difficulty, time, timestamp, gameId, moves, verified).run();

      // 清理相关缓存
      const cacheKey = D1StorageManager.createCacheKey('leaderboard', difficulty);
      this.cache.delete(cacheKey);

      return true;
    }, `D1StorageManager.saveLeaderboardRecord(${record.username})`, false);
  }

  // ⚡ 用户统计操作：获取用户统计数据
  async getUserStats(username, difficulty) {
    return await ErrorHandler.handleAsyncError(async () => {
      const { results } = await this.db.prepare(
        'SELECT * FROM user_stats WHERE username = ? AND difficulty = ?'
      ).bind(username, difficulty).all();

      // 返回统计数据或默认值
      return results[0] || {
        submissions: 0,
        bestTime: null,
        averageTime: 0,
        totalTime: 0,
        lastSubmission: null,
        suspiciousCount: 0
      };
    }, `D1StorageManager.getUserStats(${username}, ${difficulty})`, {
      submissions: 0,
      bestTime: null,
      averageTime: 0,
      totalTime: 0,
      lastSubmission: null,
      suspiciousCount: 0
    });
  }

  // ⚡ 用户统计操作：保存用户统计数据
  async saveUserStats(username, difficulty, stats) {
    return await ErrorHandler.handleAsyncError(async () => {
      await this.db.prepare(
        'INSERT OR REPLACE INTO user_stats (username, difficulty, submissions, best_time, average_time, total_time, last_submission, suspicious_count, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)'
      ).bind(
        username, difficulty, stats.submissions, stats.bestTime,
        stats.averageTime, stats.totalTime, stats.lastSubmission, stats.suspiciousCount
      ).run();

      return true;
    }, `D1StorageManager.saveUserStats(${username}, ${difficulty})`, false);
  }

  // ⚡ 速率限制操作：检查和更新速率限制
  async checkRateLimit(keyType, keyValue, limit, ttlSeconds) {
    return await ErrorHandler.handleAsyncError(async () => {
      // 清理过期记录
      await this.db.prepare('DELETE FROM rate_limits WHERE expires_at < CURRENT_TIMESTAMP').run();

      // 获取当前计数
      const { results } = await this.db.prepare(
        'SELECT count FROM rate_limits WHERE key_type = ? AND key_value = ?'
      ).bind(keyType, keyValue).all();

      const currentCount = results[0]?.count || 0;

      if (currentCount >= limit) {
        return { allowed: false, remaining: 0 };
      }

      // 增加计数，使用 INSERT OR REPLACE 确保原子性
      await this.db.prepare(
        'INSERT OR REPLACE INTO rate_limits (key_type, key_value, count, expires_at) VALUES (?, ?, ?, datetime("now", "+" || ? || " seconds"))'
      ).bind(keyType, keyValue, currentCount + 1, ttlSeconds).run();

      return { allowed: true, remaining: limit - currentCount - 1 };
    }, `D1StorageManager.checkRateLimit(${keyType}, ${keyValue})`, { allowed: false, remaining: 0 });
  }



  // ⚡ 兼容性方法：模拟 KV 的 safeGet 方法
  async safeGet(key, defaultValue = null, cacheTTL = null) {
    return await ErrorHandler.handleAsyncError(async () => {
      // 解析键格式，判断数据类型
      const keyParts = key.split(':');

      if (keyParts[0] === 'leaderboard') {
        const difficulty = keyParts[1];
        return await this.getLeaderboard(difficulty);
      }

      if (keyParts[0] === 'security' && keyParts[1] === 'user_stats') {
        const username = keyParts[2];
        const difficulty = keyParts[3];
        return await this.getUserStats(username, difficulty);
      }



      // 对于其他类型的键，返回默认值
      return defaultValue;
    }, `D1StorageManager.safeGet(${key})`, defaultValue);
  }

  // ⚡ 兼容性方法：模拟 KV 的 safePut 方法
  async safePut(key, value, options = {}) {
    return await ErrorHandler.handleAsyncError(async () => {
      // 解析键格式，判断数据类型
      const keyParts = key.split(':');

      if (keyParts[0] === 'security' && keyParts[1] === 'user_stats') {
        const username = keyParts[2];
        const difficulty = keyParts[3];
        return await this.saveUserStats(username, difficulty, value);
      }



      // 对于其他类型的键，返回成功
      return true;
    }, `D1StorageManager.safePut(${key})`, false);
  }

  // ⚡ 批量操作：批量获取数据（兼容性方法）
  async batchGet(keys) {
    return await ErrorHandler.handleAsyncError(async () => {
      const data = {};

      // 并行处理所有键
      const promises = keys.map(async (key) => {
        const result = await this.safeGet(key);
        return { key, result };
      });

      const results = await Promise.all(promises);

      results.forEach(({ key, result }) => {
        data[key] = result;
      });

      return data;
    }, 'D1StorageManager.batchGet', {});
  }

  // ⚡ 批量操作：批量设置数据（兼容性方法）
  async batchPut(operations) {
    return await ErrorHandler.handleAsyncError(async () => {
      const promises = operations.map(op =>
        this.safePut(op.key, op.value, op.options || {})
      );

      await Promise.all(promises);
      return true;
    }, 'D1StorageManager.batchPut', false);
  }

  // ⚡ 数据清理：清理过期的用户统计数据（替代 KV 的 TTL 功能）
  async cleanupExpiredUserStats(daysToKeep = 7) {
    return await ErrorHandler.handleAsyncError(async () => {
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - daysToKeep);
      const cutoffTimestamp = cutoffDate.toISOString();

      // 删除超过指定天数的用户统计数据
      const { changes } = await this.db.prepare(
        'DELETE FROM user_stats WHERE updated_at < ?'
      ).bind(cutoffTimestamp).run();

      return { deletedRecords: changes };
    }, 'D1StorageManager.cleanupExpiredUserStats', { deletedRecords: 0 });
  }

  // ⚡ 数据清理：清理过期的速率限制记录
  async cleanupExpiredRateLimits() {
    return await ErrorHandler.handleAsyncError(async () => {
      // 删除已过期的速率限制记录
      const { changes } = await this.db.prepare(
        'DELETE FROM rate_limits WHERE expires_at < CURRENT_TIMESTAMP'
      ).run();

      return { deletedRecords: changes };
    }, 'D1StorageManager.cleanupExpiredRateLimits', { deletedRecords: 0 });
  }



  // ⚡ 批量速率限制检查：优化多个限制的并发检查
  async batchCheckRateLimit(checks) {
    return await ErrorHandler.handleAsyncError(async () => {
      // 先清理过期记录
      await this.db.prepare('DELETE FROM rate_limits WHERE expires_at < CURRENT_TIMESTAMP').run();

      const results = [];

      // 并行处理所有检查
      for (const check of checks) {
        const { keyType, keyValue, limit, ttl } = check;
        const result = await this.checkRateLimit(keyType, keyValue, limit, ttl);
        results.push({ ...check, ...result });
      }

      return results;
    }, 'D1StorageManager.batchCheckRateLimit', []);
  }

  // ⚡ 性能优化：数据库健康检查和优化建议
  async performHealthCheck() {
    return await ErrorHandler.handleAsyncError(async () => {
      const healthReport = {
        timestamp: new Date().toISOString(),
        tables: {},
        performance: {},
        recommendations: []
      };

      // 检查各表的记录数量
      const tables = ['leaderboards', 'user_stats', 'rate_limits'];

      for (const table of tables) {
        const { results } = await this.db.prepare(`SELECT COUNT(*) as count FROM ${table}`).all();
        healthReport.tables[table] = results[0]?.count || 0;
      }

      // 性能建议
      if (healthReport.tables.rate_limits > 1000) {
        healthReport.recommendations.push('建议清理过期的速率限制记录');
      }

      if (healthReport.tables.user_stats > 10000) {
        healthReport.recommendations.push('建议清理过期的用户统计数据');
      }

      // 检查是否需要清理
      const { results: expiredRateLimits } = await this.db.prepare(
        'SELECT COUNT(*) as count FROM rate_limits WHERE expires_at < CURRENT_TIMESTAMP'
      ).all();

      if (expiredRateLimits[0]?.count > 0) {
        healthReport.recommendations.push(`发现 ${expiredRateLimits[0].count} 条过期速率限制记录需要清理`);
      }

      healthReport.performance.status = healthReport.recommendations.length === 0 ? 'optimal' : 'needs_attention';

      return healthReport;
    }, 'D1StorageManager.performHealthCheck', null);
  }

  // ⚡ 性能优化：自动清理过期数据
  async performMaintenance() {
    return await ErrorHandler.handleAsyncError(async () => {
      const maintenanceReport = {
        timestamp: new Date().toISOString(),
        actions: [],
        totalCleaned: 0
      };

      // 清理过期速率限制
      const rateLimitCleanup = await this.cleanupExpiredRateLimits();
      if (rateLimitCleanup.deletedRecords > 0) {
        maintenanceReport.actions.push(`清理了 ${rateLimitCleanup.deletedRecords} 条过期速率限制记录`);
        maintenanceReport.totalCleaned += rateLimitCleanup.deletedRecords;
      }

      // 清理过期用户统计（保留30天）
      const userStatsCleanup = await this.cleanupExpiredUserStats(30);
      if (userStatsCleanup.deletedRecords > 0) {
        maintenanceReport.actions.push(`清理了 ${userStatsCleanup.deletedRecords} 条过期用户统计记录`);
        maintenanceReport.totalCleaned += userStatsCleanup.deletedRecords;
      }



      maintenanceReport.status = maintenanceReport.totalCleaned > 0 ? 'completed' : 'no_action_needed';

      return maintenanceReport;
    }, 'D1StorageManager.performMaintenance', null);
  }
}

function getAllowedOrigin(request) {
  const origin = request.headers.get('Origin');
  const host = request.headers.get('Host');

  // 生产环境允许的域名白名单
  const allowedOrigins = [
    'https://cf-minesweeper.heartwopen.workers.dev',
    'https://test2.abo-vendor289.workers.dev',
    'https://test5.abo-vendor289.workers.dev',
    // 可以添加您的自定义域名
  ];

  // 本地开发环境的安全域名模式
  const localDevelopmentPatterns = [
    /^https?:\/\/localhost(:\d+)?$/,
    /^https?:\/\/127\.0\.0\.1(:\d+)?$/,
    /^https?:\/\/\[::1\](:\d+)?$/  // IPv6 localhost
  ];

  // 如果没有Origin头部（同源请求）
  if (!origin) {
    // 检查Host头部是否为允许的生产域名
    if (host) {
      const hostWithProtocol = `https://${host}`;
      if (allowedOrigins.includes(hostWithProtocol)) {
        return hostWithProtocol;
      }

      // 检查是否为本地开发环境
      const localHostWithHttp = `http://${host}`;
      const localHostWithHttps = `https://${host}`;

      for (const pattern of localDevelopmentPatterns) {
        if (pattern.test(localHostWithHttp) || pattern.test(localHostWithHttps)) {
          return localHostWithHttp; // 本地开发返回具体的origin而非通配符
        }
      }
    }

    // 默认返回第一个允许的域名
    return allowedOrigins[0];
  }

  // 验证Origin格式
  if (!isValidOriginFormat(origin)) {
    console.warn(`Invalid origin format detected: ${origin}`);
    return allowedOrigins[0];
  }

  // 检查是否在生产环境白名单中
  if (allowedOrigins.includes(origin)) {
    return origin;
  }

  // 检查是否为本地开发环境
  for (const pattern of localDevelopmentPatterns) {
    if (pattern.test(origin)) {
      return origin;
    }
  }

  // 记录可疑的跨域请求
  console.warn(`Suspicious cross-origin request from: ${origin}, IP: ${request.headers.get('CF-Connecting-IP')}`);

  // 拒绝未授权的域名，返回默认域名
  return allowedOrigins[0];
}

// 验证Origin格式的辅助函数
function isValidOriginFormat(origin) {
  try {
    const url = new URL(origin);

    // 检查协议
    if (!['http:', 'https:'].includes(url.protocol)) {
      return false;
    }

    // 检查主机名格式
    if (!url.hostname || url.hostname.length === 0) {
      return false;
    }

    // 检查是否包含路径（Origin不应该包含路径）
    if (url.pathname !== '/') {
      return false;
    }

    // 检查是否包含查询参数或片段
    if (url.search || url.hash) {
      return false;
    }

    return true;
  } catch (error) {
    return false;
  }
}

// 安全的字符串比较函数 - 防止时序攻击
function secureCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }

  if (a.length !== b.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return result === 0;
}



// 🔐 安全工具类 - 使用现代加密API
class SecurityUtils {
  // 使用 Web Crypto API 生成安全的 SHA-256 哈希
  static async generateSecureHash(data) {
    try {
      const encoder = new TextEncoder();
      const dataBuffer = encoder.encode(data);
      const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    } catch (error) {
      // 降级方案：如果 Web Crypto API 不可用，使用简单哈希
      console.warn('Web Crypto API not available, falling back to simple hash');
      return this.fallbackHash(data);
    }
  }

  // 降级哈希算法（仅在 Web Crypto API 不可用时使用）
  static fallbackHash(data) {
    let hash = 0;
    for (let i = 0; i < data.length; i++) {
      const char = data.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // 转换为32位整数
    }
    return Math.abs(hash).toString(36);
  }

  // 生成安全的客户端指纹
  static async generateSecureFingerprint(request) {
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    const userAgent = request.headers.get('User-Agent') || '';
    const acceptLanguage = request.headers.get('Accept-Language') || '';
    const acceptEncoding = request.headers.get('Accept-Encoding') || '';

    // 创建基于多个因素的指纹
    const fingerprintData = `${ip}:${userAgent}:${acceptLanguage}:${acceptEncoding}`;

    // 使用安全哈希生成指纹
    const hash = await this.generateSecureHash(fingerprintData);

    // 返回前12位作为指纹（保持与原来长度相似）
    return hash.substring(0, 12);
  }

  // 生成安全的 ETag
  static async generateSecureETag(data) {
    const str = typeof data === 'string' ? data : JSON.stringify(data);
    const hash = await this.generateSecureHash(str);

    // 返回前16位作为ETag（保持合理长度）
    return hash.substring(0, 16);
  }

  // 生成随机 nonce（用于 CSP）
  static generateNonce() {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  }
}

// 错误处理工具类
class ErrorHandler {
  static generateErrorId() {
    return Math.random().toString(36).substr(2, 9);
  }

  static async handleAsyncError(operation, context, fallbackValue = null) {
    try {
      return await operation();
    } catch (error) {
      const errorId = this.generateErrorId();
      console.error(`[${errorId}] Error in ${context}:`, error);

      // KV错误日志记录已移除以精简存储

      return fallbackValue;
    }
  }

  static handleSyncError(operation, context, fallbackValue = null) {
    try {
      return operation();
    } catch (error) {
      const errorId = this.generateErrorId();
      console.error(`[${errorId}] Error in ${context}:`, error);
      return fallbackValue;
    }
  }

  static createStandardError(type, message, statusCode = 500) {
    return {
      type,
      message,
      statusCode,
      timestamp: new Date().toISOString(),
      errorId: this.generateErrorId()
    };
  }
}

// 生成客户端指纹 - 使用安全哈希算法
async function generateClientFingerprint(request) {
  return await SecurityUtils.generateSecureFingerprint(request);
}

// 速率限制检查 - 重构为使用 D1 数据库
async function checkRateLimit(request, env) {
  return await ErrorHandler.handleAsyncError(async () => {
    const storage = new D1StorageManager(env);

    // 生成客户端指纹
    const fingerprint = await generateClientFingerprint(request);
    const minute = Math.floor(Date.now() / 60000);

    // 多层速率限制配置
    const rateLimitConfig = [
      { keyType: 'ip', keyValue: `${request.headers.get('CF-Connecting-IP')}:${minute}`, limit: 20, ttl: 120 },
      { keyType: 'fingerprint', keyValue: `${fingerprint}:${minute}`, limit: 15, ttl: 120 },
      { keyType: 'global', keyValue: `${minute}`, limit: 1000, ttl: 120 }
    ];

    // 批量检查所有限制 - 使用 D1 数据库批量操作
    const checkResults = await storage.batchCheckRateLimit(rateLimitConfig);

    // 检查是否有超限 - D1 数据库已经在 checkRateLimit 中处理了计数更新
    for (const result of checkResults) {
      if (!result.allowed) {
        // 记录速率限制触发（简化版，不依赖 logSecurityEvent）
        console.warn(`Rate limit exceeded for ${result.keyType}:${result.keyValue}, limit: ${result.limit}`);

        return { allowed: false, remaining: result.remaining, reason: '请求过于频繁' };
      }
    }

    // D1StorageManager.checkRateLimit 已经自动处理了计数更新，无需额外操作

    // 返回指纹限制的剩余次数
    const fingerprintResult = checkResults.find(r => r.keyType === 'fingerprint');
    return {
      allowed: true,
      remaining: fingerprintResult ? fingerprintResult.remaining : 0
    };
  }, 'checkRateLimit', { allowed: false, remaining: 0, reason: '系统繁忙，请稍后重试' });
}

// 游戏数据验证
function validateGameSession(gameData) {
  // 验证游戏数据结构
  if (!gameData || typeof gameData !== 'object') {
    return { valid: false, reason: '游戏数据格式无效', severity: 'critical' };
  }

  const { difficulty, time, moves, gameId, timestamp, boardSize, mineCount, gameEndTime, firstClickTime, gameState } = gameData;

  // 验证必需字段
  if (!gameId || !timestamp || !boardSize || !gameEndTime || !firstClickTime) {
    return { valid: false, reason: '缺少关键游戏会话信息', severity: 'critical' };
  }

  // 验证游戏状态
  if (gameState !== 'won') {
    return { valid: false, reason: '游戏状态无效，只能提交获胜的游戏', severity: 'high' };
  }

  // 验证时间戳合理性（极度放宽时间限制）
  const gameStartTime = new Date(timestamp).getTime();
  const now = Date.now();

  // 游戏会话不能超过7天（极度放宽限制）
  if (now - gameStartTime > 604800000) {
    return { valid: false, reason: '游戏会话已过期（超过7天）', severity: 'medium' };
  }

  // 验证游戏时长合理性（宽松验证）
  const actualGameDuration = (gameEndTime - firstClickTime) / 1000;
  const timeDifference = Math.abs(actualGameDuration - time);

  // 只检查极端情况，防止明显的作弊行为
  if (timeDifference > 60) { // 允许60秒误差
    return {
      valid: false,
      reason: '游戏时长数据不一致，请重新开始游戏',
      severity: 'high'
    };
  }

  // 验证棋盘尺寸
  const expectedBoardSizes = {
    'beginner': { width: 9, height: 9, mines: 10 },
    'intermediate': { width: 16, height: 16, mines: 40 },
    'expert': { width: 30, height: 16, mines: 99 }
  };

  const expected = expectedBoardSizes[difficulty];
  if (!expected || boardSize.width !== expected.width || boardSize.height !== expected.height || mineCount !== expected.mines) {
    return { valid: false, reason: '棋盘配置与难度不匹配', severity: 'critical' };
  }

  // 验证最小移动次数（基于难度和棋盘大小）
  const minMoves = {
    'beginner': 8,      // 9x9至少需要8次点击
    'intermediate': 15,  // 16x16至少需要15次点击
    'expert': 25        // 30x16至少需要25次点击
  };

  if (moves < minMoves[difficulty]) {
    return { valid: false, reason: `移动次数过少（${moves}次），可能存在作弊`, severity: 'critical' };
  }

  // 验证最大合理移动次数（防止无意义的点击刷数据）
  const maxMoves = boardSize.width * boardSize.height * 2; // 最多点击每个格子2次
  if (moves > maxMoves) {
    return { valid: false, reason: '移动次数过多，可能存在异常操作', severity: 'medium' };
  }

  // 验证时间与移动次数的合理性
  const avgTimePerMove = time / moves;
  if (avgTimePerMove < 0.05) { // 每次移动不能少于0.05秒（人类反应极限）
    return { valid: false, reason: '操作速度超出人类极限', severity: 'critical' };
  }

  if (avgTimePerMove > 60) { // 每次移动不能超过60秒（过于缓慢）
    return { valid: false, reason: '操作速度过于缓慢，可能存在异常', severity: 'low' };
  }

  return { valid: true, severity: 'none' };
}

// 高级成绩验证系统 - 多层防作弊机制
function validateScoreReasonableness(time, difficulty, gameData = null) {
  // 首先进行服务端游戏验证
  if (gameData) {
    const gameValidation = validateGameSession(gameData);
    if (!gameValidation.valid) {
      return {
        valid: false,
        reason: gameValidation.reason,
        severity: 'critical'
      };
    }
  }

  const minTimes = {
    'beginner': 1,      // 初级最少1秒
    'intermediate': 3,   // 中级最少3秒
    'expert': 5         // 专家最少5秒
  };

  const maxReasonableTimes = {
    'beginner': 999,    // 初级合理上限
    'intermediate': 1999, // 中级合理上限
    'expert': 2999      // 专家合理上限
  };

  // 世界纪录参考（用于检测超人类成绩）
  const worldRecords = {
    'beginner': 0.49,    // 世界纪录约0.49秒
    'intermediate': 7.03, // 世界纪录约7.03秒
    'expert': 31.133     // 世界纪录约31.133秒
  };

  if (time < minTimes[difficulty]) {
    return { valid: false, reason: '成绩过快，可能存在异常', severity: 'high' };
  }

  if (time > maxReasonableTimes[difficulty]) {
    return { valid: false, reason: '成绩超出合理范围', severity: 'low' };
  }

  // 检测超人类成绩（比世界纪录快）
  if (time < worldRecords[difficulty]) {
    return {
      valid: false,
      reason: `成绩 ${time}秒 超越了世界纪录 ${worldRecords[difficulty]}秒，请确认成绩真实性`,
      severity: 'critical'
    };
  }

  // 检测可疑的完美成绩（整数秒且过快）
  if (Number.isInteger(time) && time < worldRecords[difficulty] * 2) {
    return {
      valid: false,
      reason: '检测到可疑的完美成绩，请重新游戏',
      severity: 'medium'
    };
  }

  return { valid: true, severity: 'none' };
}

// 🧹 重构：用户行为分析 - 检测异常模式
async function analyzeUserBehavior(username, time, difficulty, env) {
  return await ErrorHandler.handleAsyncError(async () => {
    const storage = new D1StorageManager(env);

    // 获取用户统计数据 - 使用 D1 数据库
    const defaultStats = {
      submissions: 0,
      bestTime: null,
      averageTime: 0,
      totalTime: 0,
      lastSubmission: null,
      suspiciousCount: 0
    };

    const stats = await storage.getUserStats(username, difficulty);
    const now = Date.now();
    const timeSinceLastSubmission = stats.lastSubmission ?
      (now - new Date(stats.lastSubmission).getTime()) / 1000 : Infinity;

    // 行为分析配置
    const behaviorConfig = {
      frequentSubmissionWindow: 300, // 5分钟
      maxSuspiciousCount: 3,
      significantImprovementThreshold: 0.5 // 50%提升视为异常
    };

    // 检测频繁提交
    if (timeSinceLastSubmission < behaviorConfig.frequentSubmissionWindow) {
      stats.suspiciousCount++;
      if (stats.suspiciousCount > behaviorConfig.maxSuspiciousCount) {
        return {
          suspicious: true,
          reason: '检测到频繁提交行为，请适当休息后再试',
          action: 'temporary_block'
        };
      }
    } else {
      // 重置可疑计数
      stats.suspiciousCount = Math.max(0, stats.suspiciousCount - 1);
    }

    // 检测成绩异常提升 - 已禁用，允许用户自由提升成绩
    // if (stats.bestTime && time < stats.bestTime * behaviorConfig.significantImprovementThreshold) {
    //   return {
    //     suspicious: true,
    //     reason: '成绩提升过于显著，请确认游戏环境正常',
    //     action: 'review_required'
    //   };
    // }

    // 更新用户统计
    stats.submissions++;
    stats.totalTime += time;
    stats.averageTime = stats.totalTime / stats.submissions;
    stats.bestTime = stats.bestTime ? Math.min(stats.bestTime, time) : time;
    stats.lastSubmission = new Date().toISOString();

    // 保存更新的统计数据到 D1 数据库
    // 注意：D1 不支持 TTL，7天过期逻辑将通过定期清理实现
    const saveSuccess = await storage.saveUserStats(username, difficulty, stats);

    return {
      suspicious: false,
      stats,
      saveSuccess
    };
  }, 'analyzeUserBehavior', { suspicious: false, error: true });
}

// ⚡ 性能优化：智能缓存管理器
class CacheManager {
  constructor(defaultTTL = 30000) { // 默认30秒TTL
    this.cache = new Map();
    this.defaultTTL = defaultTTL;
    this.stats = {
      hits: 0,
      misses: 0,
      sets: 0,
      evictions: 0
    };
  }

  // 生成缓存键
  static createCacheKey(...parts) {
    return parts.join(':');
  }

  // 获取缓存数据
  get(key) {
    const entry = this.cache.get(key);

    if (!entry) {
      this.stats.misses++;
      return null;
    }

    // 检查是否过期
    if (Date.now() > entry.expiry) {
      this.cache.delete(key);
      this.stats.evictions++;
      this.stats.misses++;
      return null;
    }

    this.stats.hits++;
    entry.lastAccessed = Date.now();
    return entry.data;
  }

  // 设置缓存数据
  set(key, data, ttl = null) {
    const expiry = Date.now() + (ttl || this.defaultTTL);

    this.cache.set(key, {
      data,
      expiry,
      created: Date.now(),
      lastAccessed: Date.now()
    });

    this.stats.sets++;

    // 自动清理过期缓存（每100次设置操作执行一次）
    if (this.stats.sets % 100 === 0) {
      this.cleanup();
    }
  }

  // 删除缓存
  delete(key) {
    return this.cache.delete(key);
  }

  // 清理过期缓存
  cleanup() {
    const now = Date.now();
    let cleaned = 0;

    for (const [key, entry] of this.cache.entries()) {
      if (now > entry.expiry) {
        this.cache.delete(key);
        cleaned++;
      }
    }

    this.stats.evictions += cleaned;
    return cleaned;
  }

  // 获取缓存统计
  getStats() {
    const total = this.stats.hits + this.stats.misses;
    return {
      ...this.stats,
      hitRate: total > 0 ? (this.stats.hits / total * 100).toFixed(2) + '%' : '0%',
      size: this.cache.size
    };
  }

  // 清空缓存
  clear() {
    this.cache.clear();
    this.stats = { hits: 0, misses: 0, sets: 0, evictions: 0 };
  }
}

// ⚡ 性能优化：内存使用优化工具
class MemoryOptimizer {
  // 深度克隆对象（避免引用泄漏）
  static deepClone(obj) {
    if (obj === null || typeof obj !== 'object') return obj;
    if (obj instanceof Date) return new Date(obj.getTime());
    if (obj instanceof Array) return obj.map(item => this.deepClone(item));
    if (typeof obj === 'object') {
      const cloned = {};
      for (const key in obj) {
        if (obj.hasOwnProperty(key)) {
          cloned[key] = this.deepClone(obj[key]);
        }
      }
      return cloned;
    }
    return obj;
  }

  // 清理对象中的循环引用
  static removeCircularReferences(obj, seen = new WeakSet()) {
    if (obj === null || typeof obj !== 'object') return obj;
    if (seen.has(obj)) return '[Circular Reference]';

    seen.add(obj);

    if (Array.isArray(obj)) {
      return obj.map(item => this.removeCircularReferences(item, seen));
    }

    const cleaned = {};
    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        cleaned[key] = this.removeCircularReferences(obj[key], seen);
      }
    }

    return cleaned;
  }

  // 压缩字符串数据
  static compressString(str) {
    // 简单的字符串压缩（移除多余空格和换行）
    return str.replace(/\s+/g, ' ').trim();
  }

  // 内存使用监控
  static getMemoryUsage() {
    // 在Cloudflare Workers中，我们无法直接获取内存使用情况
    // 但可以估算一些关键对象的大小
    return {
      cacheSize: globalCache.cache.size,
      cacheStats: globalCache.getStats(),
      timestamp: new Date().toISOString()
    };
  }

  // 清理未使用的数据
  static cleanup() {
    // 清理过期缓存
    const cleaned = globalCache.cleanup();

    // 强制垃圾回收（如果可用）
    if (typeof gc === 'function') {
      gc();
    }

    return {
      cacheEntriesCleaned: cleaned,
      timestamp: new Date().toISOString()
    };
  }
}

// 全局缓存实例
const globalCache = new CacheManager(60000); // 60秒TTL

// ⚡ 性能优化：并发处理优化工具
class ConcurrencyOptimizer {
  constructor(maxConcurrency = 10) {
    this.maxConcurrency = maxConcurrency;
    this.running = 0;
    this.queue = [];
  }

  // 并发执行任务
  async execute(task) {
    return new Promise((resolve, reject) => {
      this.queue.push({ task, resolve, reject });
      this.processQueue();
    });
  }

  // 处理队列
  async processQueue() {
    if (this.running >= this.maxConcurrency || this.queue.length === 0) {
      return;
    }

    this.running++;
    const { task, resolve, reject } = this.queue.shift();

    try {
      const result = await task();
      resolve(result);
    } catch (error) {
      reject(error);
    } finally {
      this.running--;
      this.processQueue(); // 处理下一个任务
    }
  }

  // 批量并发执行
  async batchExecute(tasks, batchSize = null) {
    const actualBatchSize = batchSize || this.maxConcurrency;
    const results = [];

    for (let i = 0; i < tasks.length; i += actualBatchSize) {
      const batch = tasks.slice(i, i + actualBatchSize);
      const batchPromises = batch.map(task => this.execute(task));
      const batchResults = await Promise.allSettled(batchPromises);
      results.push(...batchResults);
    }

    return results;
  }

  // 获取状态
  getStatus() {
    return {
      running: this.running,
      queued: this.queue.length,
      maxConcurrency: this.maxConcurrency
    };
  }
}

// 全局并发管理器
const globalConcurrencyManager = new ConcurrencyOptimizer(8);

// 注意：在Cloudflare Workers中不能使用setInterval
// 内存清理将在需要时手动调用

// 🧹 代码质量改进：性能监控工具类
class PerformanceMonitor {
  constructor() {
    this.startTime = Date.now();
    this.checkpoints = new Map();
  }

  // 记录检查点
  checkpoint(name) {
    this.checkpoints.set(name, Date.now() - this.startTime);
  }

  // 获取总耗时
  getTotalTime() {
    return Date.now() - this.startTime;
  }

  // 获取检查点间隔
  getInterval(from, to) {
    const fromTime = this.checkpoints.get(from) || 0;
    const toTime = this.checkpoints.get(to) || this.getTotalTime();
    return toTime - fromTime;
  }

  // 生成性能报告
  getReport() {
    const report = {
      totalTime: this.getTotalTime(),
      checkpoints: Object.fromEntries(this.checkpoints),
      intervals: {}
    };

    // 计算相邻检查点的间隔
    const checkpointNames = Array.from(this.checkpoints.keys());
    for (let i = 1; i < checkpointNames.length; i++) {
      const from = checkpointNames[i - 1];
      const to = checkpointNames[i];
      report.intervals[`${from}_to_${to}`] = this.getInterval(from, to);
    }

    return report;
  }
}

// 日志功能已移除以精简KV存储

// 安全事件记录功能已移除以精简KV存储

// ⚡ 性能优化：响应优化工具类
class ResponseOptimizer {
  // 创建优化的JSON响应
  static async createOptimizedResponse(data, options = {}) {
    const {
      status = 200,
      headers = {},
      compress = true,
      cache = false,
      cacheMaxAge = 30
    } = options;

    const responseHeaders = {
      'Content-Type': 'application/json',
      'X-Content-Type-Options': 'nosniff',
      'X-Request-ID': Math.random().toString(36).substr(2, 9),
      ...headers
    };

    // 添加缓存头
    if (cache) {
      responseHeaders['Cache-Control'] = `public, max-age=${cacheMaxAge}`;
      responseHeaders['ETag'] = `"${await this.generateETag(data)}"`;
    } else {
      responseHeaders['Cache-Control'] = 'no-cache, no-store, must-revalidate';
    }

    // 压缩响应（对于大数据）
    let responseBody = JSON.stringify(data);
    if (compress && responseBody.length > 1024) {
      responseHeaders['Content-Encoding'] = 'gzip';
      // 注意：Cloudflare Workers会自动处理gzip压缩
    }

    return new Response(responseBody, {
      status,
      headers: responseHeaders
    });
  }

  // 生成ETag - 使用安全哈希算法
  static async generateETag(data) {
    return await SecurityUtils.generateSecureETag(data);
  }

  // 检查条件请求
  static checkConditionalRequest(request, etag) {
    const ifNoneMatch = request.headers.get('If-None-Match');
    if (ifNoneMatch && ifNoneMatch.includes(etag)) {
      return new Response(null, { status: 304 });
    }
    return null;
  }

  // 创建流式响应（用于大数据）
  static createStreamResponse(dataGenerator, options = {}) {
    const { headers = {} } = options;

    const stream = new ReadableStream({
      async start(controller) {
        try {
          for await (const chunk of dataGenerator()) {
            controller.enqueue(new TextEncoder().encode(JSON.stringify(chunk) + '\n'));
          }
          controller.close();
        } catch (error) {
          controller.error(error);
        }
      }
    });

    return new Response(stream, {
      headers: {
        'Content-Type': 'application/x-ndjson',
        'Transfer-Encoding': 'chunked',
        ...headers
      }
    });
  }
}

// 🧹 统一错误响应创建（安全增强版）
function createErrorResponse(code, message, status = 400, request, logDetails = {}) {
  // 安全的错误消息映射 - 避免敏感信息泄露
  const safeErrorMessages = {
    // 通用错误
    'INVALID_INPUT': '输入数据无效',
    'VALIDATION_FAILED': '数据验证失败',
    'SERVER_ERROR': '服务暂时不可用',
    'NOT_FOUND': '请求的资源不存在',
    'METHOD_NOT_ALLOWED': '请求方法不被支持',
    'UNAUTHORIZED': '访问被拒绝',

    // 用户输入相关
    'INVALID_USERNAME': '用户名格式不正确',
    'INVALID_TIME': '时间数据无效',
    'INVALID_DIFFICULTY': '难度设置无效',
    'INVALID_GAME_DATA': '游戏数据无效',

    // 业务逻辑相关
    'RATE_LIMIT_EXCEEDED': '请求过于频繁，请稍后重试',
    'UNREASONABLE_SCORE': '成绩数据异常',
    'SUSPICIOUS_BEHAVIOR': '检测到异常操作',
    'DUPLICATE_GAME': '重复提交',
    'MISSING_GAME_DATA': '游戏数据缺失'
  };

  // 使用安全的错误消息，如果没有映射则使用通用消息
  const safeMessage = safeErrorMessages[code] || '操作失败，请重试';

  // 记录详细错误信息（仅用于服务端日志）
  if (status >= 400) {
    console.warn(`Error [${code}]: ${message}`, {
      status,
      ip: request.headers.get('CF-Connecting-IP'),
      userAgent: request.headers.get('User-Agent'),
      ...logDetails
    });
  }

  // 生成请求ID用于追踪
  const requestId = Math.random().toString(36).substr(2, 9);

  return new Response(JSON.stringify({
    success: false,
    error: {
      code: code,
      message: safeMessage, // 使用安全的错误消息
      timestamp: new Date().toISOString(),
      requestId: requestId
    }
  }), {
    status: status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': getAllowedOrigin(request),
      'X-Content-Type-Options': 'nosniff',
      'X-Request-ID': requestId,
      'Cache-Control': 'no-cache, no-store, must-revalidate',
      'Pragma': 'no-cache'
    }
  });
}

// 排行榜API处理 - 增强安全性和功能
async function handleLeaderboardAPI(request, env, url) {
  const difficulty = url.pathname.split('/').pop();

  // 验证难度参数
  if (!['beginner', 'intermediate', 'expert'].includes(difficulty)) {
    return createErrorResponse('INVALID_DIFFICULTY', '无效的难度级别', 400, request);
  }

  // 速率限制检查（对所有请求）
  const rateLimitResult = await checkRateLimit(request, env);
  if (!rateLimitResult.allowed) {
    return createErrorResponse(
      'RATE_LIMIT_EXCEEDED',
      '请求过于频繁，请稍后再试',
      429,
      request
    );
  }

  if (request.method === 'GET') {
    return await ErrorHandler.handleAsyncError(async () => {
      const monitor = new PerformanceMonitor();
      const storage = new D1StorageManager(env, true); // 启用缓存

      monitor.checkpoint('start_get');

      // 检查条件请求（ETag支持）
      const cachedData = globalCache.get(CacheManager.createCacheKey('leaderboard', difficulty));

      if (cachedData) {
        const etag = await ResponseOptimizer.generateETag(cachedData);
        const conditionalResponse = ResponseOptimizer.checkConditionalRequest(request, etag);
        if (conditionalResponse) {
          return conditionalResponse;
        }
      }

      monitor.checkpoint('cache_check');

      // 获取排行榜数据 - 使用 D1 数据库
      const leaderboard = await storage.getLeaderboard(difficulty, 20);

      monitor.checkpoint('data_fetch');

      const responseData = {
        success: true,
        data: leaderboard,
        meta: {
          count: leaderboard.length,
          difficulty: difficulty,
          rateLimit: {
            remaining: rateLimitResult.remaining
          },
          serverTime: new Date().toISOString(),
          performance: monitor.getReport(),
          cacheStats: globalCache.getStats()
        }
      };

      monitor.checkpoint('response_build');

      // 使用优化的响应创建
      return await ResponseOptimizer.createOptimizedResponse(responseData, {
        cache: true,
        cacheMaxAge: 30,
        headers: {
          'Access-Control-Allow-Origin': getAllowedOrigin(request)
        }
      });
    }, 'handleLeaderboardAPI.GET', createErrorResponse('SERVER_ERROR', '获取排行榜失败', 500, request));
  }
  
  if (request.method === 'POST') {
    return await ErrorHandler.handleAsyncError(async () => {
      const monitor = new PerformanceMonitor();
      const storage = new D1StorageManager(env, true);

      monitor.checkpoint('parse_request');
      const requestData = await request.json();
      const { username, time, gameData } = requestData;

      // 快速验证：游戏数据存在性
      if (!gameData) {
        return createErrorResponse(
          'MISSING_GAME_DATA',
          '游戏数据验证失败，请重新开始游戏',
          400,
          request,
          { securityEvent: true, severity: 'critical' }
        );
      }

      monitor.checkpoint('initial_validation');

      // ⚡ 性能优化：并发执行多个验证任务
      const validationTasks = [
        () => DataValidator.validateUsername(username),
        () => DataValidator.validateTime(time),
        () => DataValidator.validateDifficulty(difficulty),
        () => DataValidator.validateGameDataStructure(gameData)
      ];

      const validationResults = await globalConcurrencyManager.batchExecute(validationTasks);

      monitor.checkpoint('concurrent_validation');

      // ⚡ 性能优化：处理并发验证结果
      const [usernameResult, timeResult, difficultyResult, gameDataResult] = validationResults.map(result =>
        result.status === 'fulfilled' ? result.value : { valid: false, reason: '验证失败' }
      );

      // 检查验证结果
      if (!usernameResult.valid) {
        return createErrorResponse('INVALID_USERNAME', usernameResult.reason, 400, request);
      }
      if (!timeResult.valid) {
        return createErrorResponse('INVALID_TIME', timeResult.reason, 400, request);
      }
      if (!difficultyResult.valid) {
        return createErrorResponse('INVALID_DIFFICULTY', difficultyResult.reason, 400, request);
      }
      if (!gameDataResult.valid) {
        return createErrorResponse('INVALID_GAME_DATA', gameDataResult.reason, 400, request);
      }

      monitor.checkpoint('validation_complete');

      // 强化的成绩验证（包含游戏数据验证）
      const scoreValidation = validateScoreReasonableness(time, difficulty, gameData);
      if (!scoreValidation.valid) {
        return createErrorResponse(
          'UNREASONABLE_SCORE',
          scoreValidation.reason,
          400,
          request,
          { securityEvent: true, severity: scoreValidation.severity }
        );
      }

      // 用户行为分析
      const behaviorAnalysis = await analyzeUserBehavior(username, time, difficulty, env);
      if (behaviorAnalysis.suspicious) {
        return createErrorResponse(
          'SUSPICIOUS_BEHAVIOR',
          behaviorAnalysis.reason,
          429,
          request,
          { securityEvent: true, action: behaviorAnalysis.action }
        );
      }

      // 获取当前排行榜数据 - 使用 D1 数据库
      const leaderboard = await storage.getLeaderboard(difficulty, 100); // 获取更多记录用于处理

      // 去除用户名的前后空格
      const trimmedUsername = username.trim();

      // 防止重复提交相同的游戏ID
      const duplicateGameId = leaderboard.find(record => record.game_id === gameData.gameId);
      if (duplicateGameId) {
        return createErrorResponse(
          'DUPLICATE_GAME',
          '该游戏已经提交过成绩，请开始新游戏',
          400,
          request,
          { securityEvent: true }
        );
      }

      // 创建成绩记录（包含更多验证信息）
      const scoreRecord = {
        username: trimmedUsername,
        difficulty: difficulty,
        time: parseInt(time),
        timestamp: new Date().toISOString(),
        gameId: gameData.gameId,
        moves: gameData.moves,
        verified: true // 标记为已验证的成绩
      };

      // 查找是否已有该用户的记录
      const existingRecord = leaderboard.find(record => record.username === trimmedUsername);

      if (existingRecord) {
        // 用户已有记录，只有更好的成绩才能更新
        if (parseInt(time) < existingRecord.time) {
          // 保存新的更好成绩到 D1 数据库
          await storage.saveLeaderboardRecord(scoreRecord);
        } else {
          // 成绩没有提升，返回当前排行榜但不更新
          const updatedLeaderboard = await storage.getLeaderboard(difficulty, 20);
          const currentRank = updatedLeaderboard.findIndex(record => record.username === trimmedUsername) + 1;
          return new Response(JSON.stringify({
            success: true,
            data: updatedLeaderboard,
            meta: {
              submitted: {
                username: trimmedUsername,
                time: parseInt(time),
                difficulty: difficulty,
                timestamp: new Date().toISOString(),
                improved: false,
                currentBest: existingRecord.time,
                rank: currentRank > 0 ? currentRank : null
              }
            }
          }), {
            headers: {
              'Content-Type': 'application/json',
              'Access-Control-Allow-Origin': getAllowedOrigin(request),
              'X-Content-Type-Options': 'nosniff',
              'X-Request-ID': Math.random().toString(36).substr(2, 9),
            },
          });
        }
      } else {
        // 新用户，保存记录到 D1 数据库
        await storage.saveLeaderboardRecord(scoreRecord);
      }

      // 获取更新后的前20名排行榜
      const top20 = await storage.getLeaderboard(difficulty, 20);

      // 🔥 关键修复：立即清理相关缓存，确保前端能获取到最新数据
      const cacheKey = CacheManager.createCacheKey('leaderboard', difficulty);
      globalCache.delete(cacheKey);

      // D1StorageManager 会自动处理缓存清理，无需手动清理

      return new Response(JSON.stringify({
        success: true,
        data: top20,
        meta: {
          submitted: {
            username: trimmedUsername,
            time: parseInt(time),
            difficulty: difficulty,
            timestamp: new Date().toISOString(),
            rank: top20.findIndex(record => record.username === trimmedUsername) + 1
          },
          rateLimit: {
            remaining: rateLimitResult.remaining
          },
          security: {
            scoreValidated: true,
            behaviorAnalyzed: true,
            requestId: Math.random().toString(36).substr(2, 9)
          }
        }
      }), {
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': getAllowedOrigin(request),
          'X-Content-Type-Options': 'nosniff',
          'X-Request-ID': Math.random().toString(36).substr(2, 9),
        },
      });
    }, 'handleLeaderboardAPI.POST', createErrorResponse('SERVER_ERROR', '提交成绩失败', 500, request));
  }

  // CORS预检请求
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      headers: {
        'Access-Control-Allow-Origin': getAllowedOrigin(request),
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, X-Requested-With',
        'Access-Control-Max-Age': '86400', // 缓存预检请求24小时
        'X-Content-Type-Options': 'nosniff',
        'Vary': 'Origin', // 告诉缓存根据Origin头部变化
      }
    });
  }
  
  return createErrorResponse('METHOD_NOT_ALLOWED', '不支持的请求方法', 405, request);
}



export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // 排行榜API路由
    if (url.pathname.startsWith('/api/leaderboard/')) {
      return handleLeaderboardAPI(request, env, url);
    }



    // 主页路由
    if (url.pathname === '/') {
      // 生成唯一的nonce值用于CSP
      const nonce = SecurityUtils.generateNonce();

      return new Response(getGameHTML(nonce), {
        headers: {
          'Content-Type': 'text/html;charset=UTF-8',
          'Cache-Control': 'no-cache, no-store, must-revalidate, max-age=0',
          'Pragma': 'no-cache',
          'Expires': '0',
          // 增强的安全头部
          'X-Content-Type-Options': 'nosniff',
          'X-Frame-Options': 'DENY',
          'X-XSS-Protection': '1; mode=block',
          'Referrer-Policy': 'strict-origin-when-cross-origin',
          // 修复的CSP策略 - 移除unsafe-inline，使用nonce
          'Content-Security-Policy': `default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'`,
          'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
          // 添加现代安全头部
          'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), speaker=()',
          'Cross-Origin-Embedder-Policy': 'require-corp',
          'Cross-Origin-Opener-Policy': 'same-origin',
          'Cross-Origin-Resource-Policy': 'same-origin',
          'X-Request-ID': Math.random().toString(36).substr(2, 9),
        },
      });
    }

    // 健康检查端点
    if (url.pathname === '/health') {
      return new Response(JSON.stringify({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        version: '2.0.1-cache-fix'
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 缓存清除端点
    if (url.pathname === '/clear-cache') {
      // 清除内存缓存
      globalCache.clear();

      return new Response(JSON.stringify({
        success: true,
        message: '缓存已清除',
        timestamp: new Date().toISOString(),
        action: '请刷新页面查看最新版本'
      }), {
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-cache, no-store, must-revalidate',
          'Pragma': 'no-cache',
          'Expires': '0'
        }
      });
    }

    return createErrorResponse('NOT_FOUND', '页面未找到', 404, request);
  },
};

function getGameHTML(nonce) {
  // 添加版本号和时间戳，强制浏览器更新缓存
  const version = `2.0.1-${Date.now()}`;
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>经典扫雷 - Classic Minesweeper</title>
    <meta name="version" content="${version}">
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
    <meta http-equiv="Pragma" content="no-cache">
    <meta http-equiv="Expires" content="0">
    <style nonce="${nonce}">
        :root {
            --cell-size: 30px;
            --counter-font-size: 24px;
            --smiley-size: 40px;

            /* 深色主题色彩系统 */
            --primary-color: #3b82f6;
            --primary-hover: #2563eb;
            --success-color: #10b981;
            --danger-color: #ef4444;
            --warning-color: #f59e0b;

            /* 背景和面板 */
            --bg-dark: #1e293b;
            --bg-darker: #0f172a;
            --panel-bg: rgba(30, 41, 59, 0.9);
            --panel-bg-light: rgba(51, 65, 85, 0.8);

            /* 文字颜色 */
            --text-primary: #f1f5f9;
            --text-secondary: #cbd5e1;
            --text-muted: #94a3b8;

            /* 阴影系统 */
            --shadow-light: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
            --shadow-medium: 0 10px 15px -3px rgba(0, 0, 0, 0.4);
            --shadow-heavy: 0 20px 25px -5px rgba(0, 0, 0, 0.5);

            /* 边框和圆角 */
            --border-radius: 12px;
            --border-radius-small: 8px;
            --border-color: rgba(148, 163, 184, 0.2);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            /* 全局禁用右键菜单和文本选择 - 增强版 */
            -webkit-touch-callout: none;
            -webkit-user-select: none;
            -khtml-user-select: none;
            -moz-user-select: none;
            -ms-user-select: none;
            user-select: none;
            /* 防止长按选择和拖拽 */
            -webkit-user-drag: none;
            -khtml-user-drag: none;
            -moz-user-drag: none;
            -o-user-drag: none;
            user-drag: none;
            /* 防止高亮显示 */
            -webkit-tap-highlight-color: transparent;
            -webkit-tap-highlight-color: rgba(0,0,0,0);
            /* 防止长按弹出菜单 */
            -webkit-touch-callout: none;
            -webkit-context-menu: none;
        }

        body {
            font-family: 'Segoe UI', 'Microsoft YaHei', sans-serif;
            background: linear-gradient(135deg, #1e293b 0%, #334155 50%, #475569 100%);
            min-height: 100vh;
            user-select: none;
            -webkit-user-select: none;
            -moz-user-select: none;
            -ms-user-select: none;
            margin: 0;
            padding: 0;
            position: relative;
            overflow-x: hidden;
            /* 禁用右键菜单但允许手势操作 */
            -webkit-touch-callout: none !important;
            -webkit-tap-highlight-color: transparent !important;
            -webkit-tap-highlight-color: rgba(0,0,0,0) !important;
            /* 防止长按弹出菜单但允许缩放拖动 */
            -webkit-context-menu: none !important;
            /* 允许所有触摸操作以提升手势灵敏度 */
            touch-action: auto !important;
            -webkit-touch-action: auto !important;
            -ms-touch-action: auto !important;
            /* 防止文本选择 */
            -webkit-text-size-adjust: none !important;
            -moz-text-size-adjust: none !important;
            -ms-text-size-adjust: none !important;
            text-size-adjust: none !important;
            /* 优化触摸滚动 */
            -webkit-overflow-scrolling: touch !important;
        }

        /* 深色主题背景装饰 */
        body::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background:
                radial-gradient(circle at 20% 80%, rgba(59, 130, 246, 0.15) 0%, transparent 50%),
                radial-gradient(circle at 80% 20%, rgba(139, 92, 246, 0.15) 0%, transparent 50%),
                radial-gradient(circle at 40% 40%, rgba(16, 185, 129, 0.1) 0%, transparent 50%);
            pointer-events: none;
            z-index: -1;
        }

        .main-container {
            display: flex;
            min-height: 100vh;
            position: relative;
        }

        .game-container {
            position: absolute;
            left: calc(280px + (100vw - 280px) / 2);
            top: max(35%, 120px);
            transform: translate(-50%, -50%);
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            z-index: 10;
        }

        .game-content {
            background: rgba(30, 41, 59, 0.9);
            backdrop-filter: blur(20px);
            border-radius: var(--border-radius);
            padding: 20px;
            border: 1px solid rgba(148, 163, 184, 0.2);
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.3);
            transition: all 0.3s ease;
        }

        .game-content:hover {
            transform: translateY(-4px);
            box-shadow: 0 35px 60px -12px rgba(0, 0, 0, 0.4);
        }

        /* 右侧控制面板 - 紧贴扫雷区右边 */
        .right-panel {
            position: absolute;
            left: calc(280px + (100vw - 280px) / 2 + 20px);
            top: 35%;
            transform: translateY(-50%);
            background: rgba(30, 41, 59, 0.9);
            backdrop-filter: blur(20px);
            border-radius: var(--border-radius);
            padding: 16px;
            border: 1px solid rgba(148, 163, 184, 0.2);
            box-shadow: var(--shadow-heavy);
            z-index: 100;
            opacity: 0;
            transition: opacity 0.3s ease;
        }

        .right-panel.positioned {
            opacity: 1;
        }
        .difficulty-selector {
            display: flex;
            flex-direction: column;
            gap: 16px;
            align-items: center;
        }

        .difficulty-buttons {
            display: flex;
            flex-direction: column;
            gap: 8px;
            width: 100%;
        }

        .difficulty-button {
            background: linear-gradient(145deg, #475569, #334155);
            border: 1px solid var(--border-color);
            border-radius: var(--border-radius-small);
            padding: 12px 18px;
            cursor: pointer;
            font-size: 13px;
            font-weight: 600;
            min-width: 80px;
            color: var(--text-primary);
            transition: all 0.2s ease;
            box-shadow: var(--shadow-light);
        }

        .difficulty-button:hover {
            background: linear-gradient(145deg, #64748b, #475569);
            transform: translateY(-2px);
            box-shadow: var(--shadow-medium);
        }

        .difficulty-button:active {
            transform: translateY(0);
            box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.3);
        }

        .difficulty-button.active {
            background: linear-gradient(145deg, var(--primary-color), var(--primary-hover));
            color: white;
            box-shadow: var(--shadow-medium);
            border-color: var(--primary-color);
        }

        .help-button {
            background: linear-gradient(145deg, var(--warning-color), #d97706);
            border: 1px solid var(--warning-color);
            border-radius: var(--border-radius-small);
            padding: 12px 18px;
            cursor: pointer;
            font-size: 13px;
            font-weight: 600;
            color: white;
            transition: all 0.2s ease;
            box-shadow: var(--shadow-light);
        }

        .help-button:hover {
            background: linear-gradient(145deg, #d97706, #b45309);
            transform: translateY(-2px);
            box-shadow: var(--shadow-medium);
        }

        .help-button:active {
            transform: translateY(0);
        }
        .game-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: linear-gradient(145deg, #334155, #1e293b);
            border-radius: var(--border-radius-small);
            padding: 12px 20px;
            margin-bottom: 16px;
            width: 100%;
            box-shadow: var(--shadow-medium);
            border: 1px solid var(--border-color);
        }

        .counter {
            background: linear-gradient(145deg, #0f172a, #1e293b);
            color: var(--danger-color);
            font-family: 'JetBrains Mono', 'Courier New', monospace;
            font-size: var(--counter-font-size);
            font-weight: bold;
            padding: 6px 12px;
            border-radius: var(--border-radius-small);
            min-width: calc(var(--counter-font-size) * 2.5);
            text-align: center;
            box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.4);
            border: 1px solid #475569;
            text-shadow: 0 0 8px rgba(239, 68, 68, 0.6);
        }

        .smiley-button {
            width: var(--smiley-size);
            height: var(--smiley-size);
            font-size: calc(var(--smiley-size) * 0.7);
            background: linear-gradient(145deg, var(--warning-color), #d97706);
            border: 2px solid var(--warning-color);
            border-radius: 50%;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.2s ease;
            box-shadow: var(--shadow-medium);
            position: relative;
        }

        .smiley-button:hover {
            transform: scale(1.08);
            box-shadow: 0 8px 25px rgba(245, 158, 11, 0.5);
        }

        .smiley-button:active {
            transform: scale(0.92);
            box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.3);
        }
        .game-board {
            background: linear-gradient(145deg, #0f172a, #1e293b);
            border-radius: var(--border-radius);
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
            box-shadow: inset 0 4px 8px rgba(0, 0, 0, 0.4);
            border: 1px solid var(--border-color);
            /* 优化手势响应性 */
            -webkit-touch-callout: none !important;
            -webkit-user-select: none !important;
            -webkit-tap-highlight-color: transparent !important;
            /* 允许所有手势操作，最大化灵敏度 */
            touch-action: auto !important;
            -webkit-touch-action: auto !important;
            -ms-touch-action: auto !important;
            /* 优化触摸性能 */
            -webkit-transform: translateZ(0);
            transform: translateZ(0);
            will-change: transform;
        }

        .board-grid {
            display: grid;
            gap: 3px;
            background: linear-gradient(145deg, #334155, #475569);
            padding: 8px;
            border-radius: var(--border-radius-small);
            box-shadow: var(--shadow-medium);
            border: 1px solid rgba(71, 85, 105, 0.5);
            /* 优化手势响应性 */
            -webkit-touch-callout: none !important;
            -webkit-user-select: none !important;
            /* 允许所有手势操作 */
            touch-action: auto !important;
            /* 优化渲染性能 */
            -webkit-transform: translateZ(0);
            transform: translateZ(0);
        }

        /* 未挖掘格子 - 更亮的金属质感 */
        .cell {
            width: var(--cell-size);
            height: var(--cell-size);
            background: linear-gradient(145deg, #64748b, #475569);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: calc(var(--cell-size) * 0.65);
            font-weight: 800;
            cursor: pointer;
            border-radius: 4px;
            transition: all 0.2s ease;
            border: 1px solid #94a3b8;
            box-shadow:
                0 2px 4px rgba(0, 0, 0, 0.3),
                inset 0 1px 0 rgba(203, 213, 225, 0.3);
            position: relative;
            /* 只禁用右键菜单和文本选择，允许作为缩放拖动的一部分 */
            -webkit-touch-callout: none !important;
            -webkit-user-select: none !important;
            -webkit-tap-highlight-color: transparent !important;
            /* 防止长按选择菜单 */
            -webkit-context-menu: none !important;
            -moz-context-menu: none !important;
        }

        .cell:hover {
            background: linear-gradient(145deg, #94a3b8, #64748b);
            transform: scale(1.05);
            box-shadow:
                0 4px 8px rgba(0, 0, 0, 0.4),
                inset 0 1px 0 rgba(203, 213, 225, 0.4);
        }

        .cell:active {
            transform: scale(0.95);
            box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.4);
        }

        /* 已挖掘格子 - 柔和的浅灰色，不刺眼 */
        .cell.revealed {
            background: linear-gradient(145deg, #e2e8f0, #cbd5e1);
            box-shadow:
                inset 0 2px 4px rgba(0, 0, 0, 0.1),
                inset 0 -1px 0 rgba(255, 255, 255, 0.4);
            border: 1px solid #94a3b8;
            color: #1e293b;
        }

        .cell.revealed:hover {
            background: linear-gradient(145deg, #f1f5f9, #e2e8f0);
            transform: none;
        }

        .cell.mine {
            background: linear-gradient(145deg, #ef4444, #dc2626) !important;
            color: #ffffff;
            border: 2px solid #fca5a5 !important;
            animation: mineExplode 0.4s ease-out;
            box-shadow:
                0 0 20px rgba(239, 68, 68, 0.6),
                inset 0 2px 4px rgba(0, 0, 0, 0.3);
        }

        @keyframes mineExplode {
            0% { transform: scale(1); box-shadow: 0 0 20px rgba(239, 68, 68, 0.6); }
            50% { transform: scale(1.15); box-shadow: 0 0 30px rgba(239, 68, 68, 0.8); }
            100% { transform: scale(1); box-shadow: 0 0 20px rgba(239, 68, 68, 0.6); }
        }

        .cell.flagged::after {
            content: '🚩';
            font-size: calc(var(--cell-size) * 0.75);
            animation: flagWave 0.3s ease-out;
            filter: drop-shadow(0 2px 4px rgba(0, 0, 0, 0.3));
        }

        @keyframes flagWave {
            0% { transform: scale(0) rotate(-10deg); }
            50% { transform: scale(1.2) rotate(5deg); }
            100% { transform: scale(1) rotate(0deg); }
        }

        /* 数字颜色 - 高对比度，清晰可见 */
        .cell[class*="number-"] { font-weight: 900; text-shadow: 0 1px 3px rgba(0,0,0,0.3); }
        .cell.number-1 { color: #1e40af; }
        .cell.number-2 { color: #047857; }
        .cell.number-3 { color: #b91c1c; }
        .cell.number-4 { color: #6b21a8; }
        .cell.number-5 { color: #991b1b; }
        .cell.number-6 { color: #0c4a6e; }
        .cell.number-7 { color: #111827; }
        .cell.number-8 { color: #374151; }

        .cell.quick-dig-highlight {
            background: linear-gradient(145deg, #fbbf24, #f59e0b) !important;
            border: 2px solid #fbbf24 !important;
            box-shadow:
                0 0 20px rgba(251, 191, 36, 0.6) !important,
                inset 0 1px 0 rgba(255, 255, 255, 0.3) !important;
            animation: quickDigPulse 0.8s ease-in-out infinite alternate;
        }

        @keyframes quickDigPulse {
            0% {
                transform: scale(1);
                box-shadow: 0 0 20px rgba(251, 191, 36, 0.6);
            }
            100% {
                transform: scale(1.08);
                box-shadow: 0 0 30px rgba(251, 191, 36, 0.8);
            }
        }
        
        /* 排行榜面板样式 - 固定左侧 */
        .leaderboard-panel {
            position: fixed;
            left: 0;
            top: 0;
            width: 280px;
            height: 100vh;
            background: rgba(30, 41, 59, 0.95);
            backdrop-filter: blur(20px);
            padding: 16px 12px;
            overflow-y: auto;
            border-right: 1px solid rgba(148, 163, 184, 0.2);
            z-index: 100;
            transition: transform 0.3s ease;
        }

        .leaderboard-panel.hidden {
            transform: translateX(-100%);
        }

        .leaderboard-header h3 {
            margin: 0 0 12px 0;
            font-size: 18px;
            text-align: center;
            color: var(--text-primary);
            font-weight: 700;
            text-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
        }

        .leaderboard-tabs {
            display: flex;
            gap: 4px;
            margin-bottom: 16px;
            background: rgba(0, 0, 0, 0.2);
            padding: 4px;
            border-radius: var(--border-radius-small);
            border: 1px solid var(--border-color);
        }

        .tab-button {
            flex: 1;
            padding: 8px 6px;
            font-size: 11px;
            background: transparent;
            border: none;
            cursor: pointer;
            border-radius: 4px;
            transition: all 0.2s ease;
            font-weight: 600;
            color: var(--text-muted);
        }

        .tab-button:hover {
            background: rgba(148, 163, 184, 0.2);
            color: var(--text-secondary);
        }

        .tab-button.active {
            background: linear-gradient(145deg, var(--primary-color), var(--primary-hover));
            color: white;
            box-shadow: var(--shadow-light);
        }

        .leaderboard-list {
            display: block;
        }

        .leaderboard-item {
            display: flex;
            align-items: center;
            padding: 8px 12px;
            margin: 3px 0;
            background: linear-gradient(145deg, rgba(51, 65, 85, 0.8), rgba(30, 41, 59, 0.6));
            border-radius: var(--border-radius-small);
            font-size: 12px;
            transition: all 0.2s ease;
            border: 1px solid var(--border-color);
        }

        .leaderboard-item:hover {
            background: linear-gradient(145deg, rgba(71, 85, 105, 0.9), rgba(51, 65, 85, 0.7));
            transform: translateX(6px);
            box-shadow: var(--shadow-light);
        }

        .leaderboard-rank {
            font-weight: 800;
            color: var(--text-muted);
            min-width: 28px;
            text-align: center;
            font-size: 13px;
        }

        .leaderboard-item:nth-child(1) .leaderboard-rank { color: #fbbf24; }
        .leaderboard-item:nth-child(2) .leaderboard-rank { color: #e5e7eb; }
        .leaderboard-item:nth-child(3) .leaderboard-rank { color: #d97706; }

        .leaderboard-username {
            flex: 1;
            margin: 0 10px;
            font-weight: 600;
            color: var(--text-primary);
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .leaderboard-time {
            font-family: 'JetBrains Mono', 'Courier New', monospace;
            font-weight: 700;
            color: var(--danger-color);
            font-size: 11px;
            background: rgba(239, 68, 68, 0.2);
            padding: 4px 8px;
            border-radius: 4px;
            border: 1px solid rgba(239, 68, 68, 0.3);
        }
        
        /* 模态框样式 */
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.6);
            backdrop-filter: blur(4px);
            animation: modalFadeIn 0.3s ease-out;
        }

        @keyframes modalFadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }

        .modal-content {
            background: linear-gradient(145deg, #1e293b, #0f172a);
            backdrop-filter: blur(20px);
            position: absolute;
            top: max(40%, 250px);
            left: 50%;
            transform: translate(-50%, -50%);
            padding: 32px;
            border-radius: var(--border-radius);
            width: 90%;
            max-width: 450px;
            text-align: center;
            box-shadow: var(--shadow-heavy);
            border: 2px solid rgba(148, 163, 184, 0.3);
            animation: modalFadeInDirect 0.2s ease-out;
            color: var(--text-primary);
        }

        @keyframes modalSlideIn {
            from {
                transform: translateY(-50px) scale(0.9);
                opacity: 0;
            }
            to {
                transform: translateY(0) scale(1);
                opacity: 1;
            }
        }

        @keyframes modalFadeInDirect {
            from {
                transform: translate(-50%, -50%) scale(0.95);
                opacity: 0;
            }
            to {
                transform: translate(-50%, -50%) scale(1);
                opacity: 1;
            }
        }

        .modal-button {
            background: linear-gradient(145deg, var(--primary-color), var(--primary-hover));
            border: 1px solid var(--primary-color);
            border-radius: var(--border-radius-small);
            padding: 12px 20px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            margin: 6px;
            transition: all 0.2s ease;
            color: white;
            box-shadow: var(--shadow-medium);
        }

        .modal-button:hover {
            background: linear-gradient(145deg, var(--primary-hover), #1e40af);
            transform: translateY(-1px);
            box-shadow: var(--shadow-heavy);
        }

        .modal-button:active {
            transform: translateY(0);
            box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.2);
        }

        .modal-input {
            width: 100%;
            padding: 12px 16px;
            border: 2px solid #475569;
            border-radius: var(--border-radius-small);
            font-size: 14px;
            margin: 16px 0;
            box-sizing: border-box;
            transition: all 0.2s ease;
            background: linear-gradient(145deg, #334155, #1e293b);
            color: var(--text-primary);
        }

        .modal-input:focus {
            outline: none;
            border-color: var(--primary-color);
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.3);
            background: linear-gradient(145deg, #475569, #334155);
        }

        .modal-input::placeholder {
            color: var(--text-muted);
        }

        /* 为输入框恢复文本选择功能 */
        .modal-input {
            -webkit-user-select: text !important;
            -moz-user-select: text !important;
            -ms-user-select: text !important;
            user-select: text !important;
        }

        /* 模态框内容样式 - 高对比度 */
        #modal-title {
            color: var(--text-primary) !important;
            font-weight: 700 !important;
            text-shadow: 0 1px 2px rgba(0, 0, 0, 0.3) !important;
        }

        #modal-message {
            color: var(--text-secondary) !important;
            line-height: 1.6 !important;
        }

        #modal-icon {
            filter: drop-shadow(0 2px 4px rgba(0, 0, 0, 0.3)) !important;
        }

        /* 取消按钮特殊样式 */
        #modal-cancel {
            background: linear-gradient(145deg, #6b7280, #4b5563) !important;
            border-color: #6b7280 !important;
        }

        #modal-cancel:hover {
            background: linear-gradient(145deg, #4b5563, #374151) !important;
        }

        /* 移动端排行榜按钮 - 默认隐藏 */
        .mobile-leaderboard-button {
            display: none;
        }

        /* 移动端排行榜模态框 */
        .mobile-leaderboard-modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.8);
            z-index: 10000;
            backdrop-filter: blur(10px);
        }

        .mobile-leaderboard-modal.show {
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .mobile-leaderboard-content {
            background: var(--panel-bg);
            border-radius: var(--border-radius);
            width: 90%;
            max-width: 400px;
            max-height: 80vh;
            overflow: hidden;
            box-shadow: var(--shadow-heavy);
            border: 1px solid var(--border-color);
        }

        .mobile-leaderboard-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 16px 20px;
            border-bottom: 1px solid var(--border-color);
            background: var(--panel-bg-light);
        }

        .mobile-leaderboard-header h3 {
            margin: 0;
            color: var(--text-primary);
            font-size: 18px;
        }

        .mobile-leaderboard-close {
            background: none;
            border: none;
            color: var(--text-secondary);
            font-size: 24px;
            cursor: pointer;
            padding: 4px 8px;
            border-radius: 4px;
            transition: all 0.3s ease;
        }

        .mobile-leaderboard-close:hover {
            background: rgba(255, 255, 255, 0.1);
            color: var(--text-primary);
        }

        .mobile-leaderboard-tabs {
            display: flex;
            background: var(--panel-bg-light);
            border-bottom: 1px solid var(--border-color);
        }

        .mobile-tab-button {
            flex: 1;
            padding: 12px 8px;
            background: none;
            border: none;
            color: var(--text-secondary);
            font-size: 12px;
            cursor: pointer;
            transition: all 0.3s ease;
            border-bottom: 2px solid transparent;
        }

        .mobile-tab-button.active {
            color: var(--primary-color);
            border-bottom-color: var(--primary-color);
            background: rgba(59, 130, 246, 0.1);
        }

        .mobile-tab-button:hover {
            background: rgba(255, 255, 255, 0.05);
            color: var(--text-primary);
        }

        .mobile-leaderboard-list {
            max-height: 50vh;
            overflow-y: auto;
            padding: 16px;
        }

        /* 移动端排行榜滚动条美化 */
        .mobile-leaderboard-list::-webkit-scrollbar {
            width: 6px;
        }

        .mobile-leaderboard-list::-webkit-scrollbar-track {
            background: rgba(0, 0, 0, 0.1);
            border-radius: 3px;
        }

        .mobile-leaderboard-list::-webkit-scrollbar-thumb {
            background: linear-gradient(145deg, var(--primary-color), var(--primary-hover));
            border-radius: 3px;
        }

        .mobile-leaderboard-list::-webkit-scrollbar-thumb:hover {
            background: linear-gradient(145deg, var(--primary-hover), #1e40af);
        }

        /* 响应式设计 */
        @media (max-width: 1200px) {
            .leaderboard-panel {
                position: relative;
                width: 100%;
                height: auto;
                max-height: 250px;
                margin-bottom: 20px;
            }

            .main-container {
                flex-direction: column;
            }

            .game-container {
                position: relative;
                left: auto;
                top: auto;
                transform: none;
                margin: 20px auto;
            }

            .right-panel {
                position: relative !important;
                left: auto !important;
                top: auto !important;
                transform: none !important;
                margin: 20px auto;
                width: fit-content;
            }

            .difficulty-buttons {
                flex-direction: row;
            }

            .modal {
                left: 0;
                width: 100%;
            }

            .modal-content {
                top: 50%;
                transform: translate(-50%, -50%);
            }
        }

        @media (max-width: 768px) {
            .leaderboard-panel {
                display: none;
            }

            .game-container {
                position: absolute;
                left: 50%;
                top: max(35%, 120px);
                transform: translate(-50%, -50%);
                max-width: 95vw;
                max-height: 70vh;
            }

            .right-panel {
                position: fixed !important;
                bottom: 20px !important;
                right: 20px !important;
                left: auto !important;
                top: auto !important;
                transform: none !important;
                padding: 12px;
            }

            .game-content {
                padding: 16px;
            }

            :root {
                --cell-size: 22px;
                --counter-font-size: 16px;
                --smiley-size: 28px;
                --border-radius: 8px;
                --border-radius-small: 6px;
            }

            .difficulty-buttons {
                gap: 4px;
                flex-direction: row;
            }

            .difficulty-button {
                padding: 6px 10px;
                font-size: 10px;
                min-width: 50px;
            }

            .help-button {
                padding: 6px 10px;
                font-size: 10px;
            }

            .mobile-leaderboard-button {
                display: block !important;
                padding: 6px 10px;
                font-size: 10px;
                background: linear-gradient(145deg, var(--primary-color), var(--primary-hover));
                color: white;
                border: none;
                border-radius: var(--border-radius-small);
                cursor: pointer;
                transition: all 0.3s ease;
                margin-top: 8px;
                width: 100%;
                text-align: center;
            }

            .mobile-leaderboard-button:hover {
                background: linear-gradient(145deg, var(--primary-hover), #1e40af);
                transform: translateY(-1px);
            }

            .game-header {
                padding: 8px 12px;
            }

            .modal {
                left: 0;
                width: 100%;
            }

            .modal-content {
                top: 50%;
                transform: translate(-50%, -50%);
                padding: 20px;
            }
        }

        @media (max-width: 480px) {
            :root {
                --cell-size: 20px;
                --counter-font-size: 14px;
                --smiley-size: 26px;
            }

            .game-container {
                padding: 12px;
            }

            .difficulty-selector {
                flex-direction: column;
                gap: 12px;
                align-items: stretch;
            }

            .difficulty-buttons {
                justify-content: center;
            }

            .game-header {
                padding: 10px 12px;
            }
        }





        /* 滚动条美化 */
        .leaderboard-panel::-webkit-scrollbar {
            width: 6px;
        }

        .leaderboard-panel::-webkit-scrollbar-track {
            background: rgba(0, 0, 0, 0.1);
            border-radius: 3px;
        }

        .leaderboard-panel::-webkit-scrollbar-thumb {
            background: linear-gradient(145deg, var(--primary-color), var(--primary-hover));
            border-radius: 3px;
        }

        .leaderboard-panel::-webkit-scrollbar-thumb:hover {
            background: linear-gradient(145deg, var(--primary-hover), #1e40af);
        }

        /* 页脚样式 */
        .footer {
            position: fixed;
            bottom: 0;
            left: 280px;
            right: 0;
            background: rgba(15, 23, 42, 0.95);
            backdrop-filter: blur(20px);
            border-top: 1px solid rgba(148, 163, 184, 0.2);
            padding: 8px 20px;
            z-index: 1000;
            box-shadow: 0 -4px 6px -1px rgba(0, 0, 0, 0.3);
        }

        .footer-content {
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 16px;
        }

        .footer-title {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 14px;
            font-weight: 600;
            color: var(--text-primary);
        }

        .footer-icon {
            font-size: 16px;
            animation: pulse 2s ease-in-out infinite;
        }

        @keyframes pulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.1); }
        }

        .footer-name {
            background: linear-gradient(135deg, var(--primary-color), var(--success-color));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            font-weight: 700;
        }

        .github-link {
            display: flex;
            align-items: center;
            justify-content: center;
            width: 36px;
            height: 36px;
            background: linear-gradient(145deg, #374151, #1f2937);
            border-radius: 50%;
            color: var(--text-secondary);
            text-decoration: none;
            transition: all 0.3s ease;
            border: 1px solid rgba(148, 163, 184, 0.2);
            box-shadow: var(--shadow-light);
        }

        .github-link:hover {
            background: linear-gradient(145deg, #4b5563, #374151);
            color: var(--text-primary);
            transform: translateY(-2px) scale(1.05);
            box-shadow: var(--shadow-medium);
        }

        .github-icon {
            width: 20px;
            height: 20px;
            transition: transform 0.3s ease;
        }

        .github-link:hover .github-icon {
            transform: rotate(360deg);
        }

        /* 响应式页脚 */
        @media (max-width: 1200px) {
            .footer {
                left: 0;
                right: 0;
            }
        }

        @media (max-width: 768px) {
            .footer {
                padding: 6px 16px;
                left: 0;
                right: 0;
            }

            .footer-title {
                font-size: 12px;
            }

            .footer-icon {
                font-size: 14px;
            }

            .github-link {
                width: 28px;
                height: 28px;
            }

            .github-icon {
                width: 16px;
                height: 16px;
            }

            .footer-content {
                gap: 12px;
            }
        }
    </style>
</head>
<body>
    <div class="main-container">
        <!-- 排行榜面板 -->
        <div class="leaderboard-panel">
            <div class="leaderboard-header">
                <h3>🏆 排行榜</h3>
                <div class="leaderboard-tabs">
                    <button class="tab-button active" data-difficulty="beginner">初级</button>
                    <button class="tab-button" data-difficulty="intermediate">中级</button>
                    <button class="tab-button" data-difficulty="expert">专家</button>
                </div>
            </div>
            <div class="leaderboard-list" id="leaderboard-list">
                <div style="text-align: center; padding: 20px; color: #666;">加载中...</div>
            </div>
        </div>

        <!-- 游戏区域 -->
        <div class="game-container">
            <div class="game-content">
                <div class="game-header">
                    <div class="counter" id="mine-counter">010</div>
                    <button class="smiley-button" id="smiley-button">😊</button>
                    <div class="counter" id="timer">000</div>
                </div>

                <div class="game-board">
                    <div class="board-grid" id="board-grid"></div>
                </div>
            </div>
        </div>

        <!-- 右侧控制面板 -->
        <div class="right-panel">
            <div class="difficulty-selector">
                <div class="difficulty-buttons">
                    <button class="difficulty-button active" data-difficulty="beginner">初级</button>
                    <button class="difficulty-button" data-difficulty="intermediate">中级</button>
                    <button class="difficulty-button" data-difficulty="expert">专家</button>
                </div>
                <button class="help-button" id="help-button">帮助</button>
                <button class="mobile-leaderboard-button" id="mobile-leaderboard-button">🏆 排行榜</button>
            </div>
        </div>
    </div>

    <!-- 模态框 -->
    <div id="game-modal" class="modal">
        <div class="modal-content">
            <div id="modal-icon" style="font-size: 42px; margin-bottom: 12px;">😊</div>
            <div id="modal-title" style="font-size: 18px; font-weight: bold; margin-bottom: 15px;">游戏提示</div>
            <div id="modal-message" style="margin-bottom: 20px;">消息内容</div>
            <div id="modal-input-container" style="display: none;">
                <input type="text" id="modal-input" class="modal-input" placeholder="请输入您的用户名（最多8个汉字或16个字符）" maxlength="16">
            </div>
            <div>
                <button id="modal-cancel" class="modal-button" style="display: none;">取消</button>
                <button id="modal-confirm" class="modal-button">确定</button>
            </div>
        </div>
    </div>

    <!-- 移动端排行榜模态框 -->
    <div id="mobile-leaderboard-modal" class="mobile-leaderboard-modal">
        <div class="mobile-leaderboard-content">
            <div class="mobile-leaderboard-header">
                <h3>🏆 排行榜</h3>
                <button class="mobile-leaderboard-close" id="mobile-leaderboard-close">×</button>
            </div>
            <div class="mobile-leaderboard-tabs">
                <button class="mobile-tab-button active" data-difficulty="beginner">初级</button>
                <button class="mobile-tab-button" data-difficulty="intermediate">中级</button>
                <button class="mobile-tab-button" data-difficulty="expert">专家</button>
            </div>
            <div class="mobile-leaderboard-list" id="mobile-leaderboard-list">
                <div style="text-align: center; padding: 20px; color: #666;">加载中...</div>
            </div>
        </div>
    </div>

    <!-- 页脚 -->
    <footer class="footer">
        <div class="footer-content">
            <div class="footer-title">
                <span class="footer-icon">💣</span>
                <span class="footer-name">cf-minesweeper</span>
            </div>
            <a href="https://github.com/kadidalax/cf-minesweeper" target="_blank" class="github-link" title="查看源代码">
                <svg class="github-icon" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
                </svg>
            </a>
        </div>
    </footer>

    <script nonce="${nonce}">
        // 简化的扫雷游戏类 - 基于simple.js优化
        class MinesweeperGame {
            constructor() {
                this.difficulties = {
                    beginner: { rows: 9, cols: 9, mines: 10 },
                    intermediate: { rows: 16, cols: 16, mines: 40 },
                    expert: { rows: 16, cols: 30, mines: 99 }
                };
                this.currentDifficulty = 'beginner';
                this.board = [];
                this.revealed = [];
                this.flagged = [];
                this.gameState = 'ready';
                this.firstClick = true;
                this.startTime = null;
                this.timer = null;
                this.mineCount = 0;
                this.flagCount = 0;

                // 游戏验证所需的状态追踪
                this.moveCount = 0;
                this.gameId = null;
                this.gameStartTime = null;
                this.firstClickTime = null;
                this.rows = 0;
                this.cols = 0;

                // 简化的双键快速挖掘状态
                this.mouseButtons = {
                    left: false,
                    right: false
                };
                this.quickDigCell = null;

                // DOM元素缓存
                this.cellElements = null;
                this.domElements = {
                    smileyButton: null,
                    timer: null,
                    mineCounter: null,
                    boardGrid: null
                };
            }

            initGame() {
                const config = this.difficulties[this.currentDifficulty];
                this.rows = config.rows;
                this.cols = config.cols;
                this.mineCount = config.mines;
                this.flagCount = 0;

                this.board = Array(this.rows).fill().map(() => Array(this.cols).fill(0));
                this.revealed = Array(this.rows).fill().map(() => Array(this.cols).fill(false));
                this.flagged = Array(this.rows).fill().map(() => Array(this.cols).fill(false));

                this.gameState = 'ready';
                this.firstClick = true;
                this.startTime = null;

                // 初始化游戏验证所需的状态
                this.moveCount = 0;
                this.gameId = 'game_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
                this.gameStartTime = new Date().toISOString();
                this.firstClickTime = null;

                if (this.timer) {
                    clearInterval(this.timer);
                    this.timer = null;
                }

                this.createBoard();
                this.updateDisplay();

                this.getDomElement('smileyButton', 'smiley-button').textContent = '😊';
                this.getDomElement('timer', 'timer').textContent = '000';

                // 延迟更新位置，确保DOM渲染完成
                setTimeout(() => {
                    this.updateGamePosition();
                    this.updateRightPanelPosition();
                }, 100);
            }

            createBoard() {
                const boardGrid = this.getDomElement('boardGrid', 'board-grid');
                boardGrid.innerHTML = '';

                // 清除DOM元素缓存
                this.clearCellCache();

                // 简化的响应式计算
                this.calculateCellSize();

                boardGrid.style.gridTemplateColumns = 'repeat(' + this.cols + ', var(--cell-size))';
                boardGrid.style.gridTemplateRows = 'repeat(' + this.rows + ', var(--cell-size))';

                for (let row = 0; row < this.rows; row++) {
                    for (let col = 0; col < this.cols; col++) {
                        const cell = document.createElement('div');
                        cell.className = 'cell';

                        // 阻止右键菜单
                        cell.addEventListener('contextmenu', (e) => {
                            e.preventDefault();
                            e.stopPropagation();
                            return false;
                        });

                        // 鼠标事件
                        cell.addEventListener('mousedown', (e) => this.handleMouseDown(row, col, e));
                        cell.addEventListener('mouseup', (e) => this.handleMouseUp(row, col, e));

                        // 触摸支持 - 优化版本，提升拖动和缩放灵敏度
                        let touchTimer = null;
                        let touchStartTime = 0;
                        let touchMoved = false;
                        let lastTouchTime = 0;
                        let doubleTapTimer = null;
                        let initialTouchPos = null;
                        let isGestureMode = false;

                        cell.addEventListener('touchstart', (e) => {
                            // 立即检测多点触摸（缩放手势）
                            if (e.touches.length > 1) {
                                isGestureMode = true;
                                // 清理所有游戏相关定时器
                                if (touchTimer) {
                                    clearTimeout(touchTimer);
                                    touchTimer = null;
                                }
                                if (doubleTapTimer) {
                                    clearTimeout(doubleTapTimer);
                                    doubleTapTimer = null;
                                }
                                // 多点触摸时完全不干预，让浏览器处理缩放
                                return;
                            }

                            isGestureMode = false;
                            touchStartTime = Date.now();
                            touchMoved = false;

                            // 记录初始触摸位置
                            initialTouchPos = {
                                x: e.touches[0].clientX,
                                y: e.touches[0].clientY
                            };

                            // 只在确定是游戏操作时才阻止默认行为
                            // 先不阻止，让浏览器开始处理，后续根据移动距离判断

                            // 检测双击
                            const timeSinceLastTouch = touchStartTime - lastTouchTime;
                            if (timeSinceLastTouch < 300 && timeSinceLastTouch > 50) {
                                // 双击检测成功，立即阻止默认行为
                                e.preventDefault();
                                e.stopPropagation();

                                if (doubleTapTimer) {
                                    clearTimeout(doubleTapTimer);
                                    doubleTapTimer = null;
                                }

                                // 检查是否为已挖掘的数字格子
                                if (this.revealed[row][col] && this.board[row][col] > 0) {
                                    // 执行快速挖掘
                                    this.handleMobileQuickDig(row, col, e);
                                    if (navigator.vibrate) navigator.vibrate([30, 50, 30]); // 双击振动模式
                                    return; // 双击时不执行其他逻辑
                                }
                            }

                            lastTouchTime = touchStartTime;

                            // 延迟启动长按定时器，给拖动操作更多时间
                            touchTimer = setTimeout(() => {
                                if (!touchMoved && !isGestureMode) {
                                    // 确认是长按操作，阻止默认行为
                                    e.preventDefault();
                                    this.handleRightClick(row, col, e);
                                    if (navigator.vibrate) navigator.vibrate(50);
                                }
                            }, 600); // 增加到600ms，给拖动更多时间
                        }, { passive: true }); // 使用passive模式提升性能

                        cell.addEventListener('touchend', (e) => {
                            // 检测是否还有其他触摸点
                            if (e.touches.length > 0) {
                                // 还有其他触摸点，可能是多点手势的一部分
                                return;
                            }

                            // 如果是手势模式，重置状态但不处理游戏逻辑
                            if (isGestureMode) {
                                isGestureMode = false;
                                touchMoved = false;
                                return;
                            }

                            // 单点触摸结束 - 只有在确定不是拖动时才处理游戏逻辑
                            if (touchTimer) {
                                clearTimeout(touchTimer);
                                touchTimer = null;

                                // 只有在没有移动且时间较短时才触发左键点击
                                if (!touchMoved && (Date.now() - touchStartTime) < 500) {
                                    // 确认是点击操作，阻止默认行为
                                    e.preventDefault();
                                    e.stopPropagation();

                                    // 延迟执行左键点击，等待可能的双击
                                    doubleTapTimer = setTimeout(() => {
                                        this.handleLeftClick(row, col, e);
                                    }, 250);
                                }
                            }

                            // 重置状态
                            touchMoved = false;
                            initialTouchPos = null;
                        }, { passive: true }); // 使用passive提升性能

                        cell.addEventListener('touchmove', (e) => {
                            // 立即检测多点触摸（缩放手势）
                            if (e.touches.length > 1) {
                                isGestureMode = true;
                                touchMoved = true;
                                // 多点触摸时完全不干预，清理游戏定时器
                                if (touchTimer) {
                                    clearTimeout(touchTimer);
                                    touchTimer = null;
                                }
                                if (doubleTapTimer) {
                                    clearTimeout(doubleTapTimer);
                                    doubleTapTimer = null;
                                }
                                return; // 让浏览器处理缩放
                            }

                            // 单点移动 - 计算移动距离
                            if (initialTouchPos) {
                                const currentTouch = e.touches[0];
                                const deltaX = Math.abs(currentTouch.clientX - initialTouchPos.x);
                                const deltaY = Math.abs(currentTouch.clientY - initialTouchPos.y);
                                const moveDistance = Math.sqrt(deltaX * deltaX + deltaY * deltaY);

                                // 如果移动距离超过阈值，认为是拖动操作
                                if (moveDistance > 10) { // 10px阈值，比较敏感
                                    touchMoved = true;

                                    // 清理游戏操作定时器
                                    if (touchTimer) {
                                        clearTimeout(touchTimer);
                                        touchTimer = null;
                                    }
                                    if (doubleTapTimer) {
                                        clearTimeout(doubleTapTimer);
                                        doubleTapTimer = null;
                                    }

                                    // 不阻止默认行为，让浏览器处理拖动
                                    return;
                                }
                            }

                            // 小幅移动时仍然阻止默认行为（防止意外触发）
                            if (!isGestureMode) {
                                e.preventDefault();
                            }
                        }, { passive: false });

                        boardGrid.appendChild(cell);
                    }
                }
            }

            // 优化的格子大小计算 - 确保一页显示所有格子
            calculateCellSize() {
                const viewportWidth = window.innerWidth;
                const viewportHeight = window.innerHeight;

                // 为排行榜、游戏头部、按钮等预留空间
                const leaderboardWidth = window.innerWidth > 1200 ? 280 : 0;
                const reservedWidth = leaderboardWidth + 200; // 为右侧面板预留更多空间
                const reservedHeight = 300; // 头部、按钮、边距等

                const availableWidth = viewportWidth - reservedWidth;
                const availableHeight = viewportHeight - reservedHeight;

                const maxCellSizeByWidth = Math.floor(availableWidth / this.cols);
                const maxCellSizeByHeight = Math.floor(availableHeight / this.rows);

                // 确保格子大小适中，优先保证全部显示
                let optimalSize = Math.min(maxCellSizeByWidth, maxCellSizeByHeight);
                optimalSize = Math.max(16, Math.min(35, optimalSize));

                document.documentElement.style.setProperty('--cell-size', optimalSize + 'px');
                document.documentElement.style.setProperty('--counter-font-size', Math.max(14, optimalSize * 0.6) + 'px');
                document.documentElement.style.setProperty('--smiley-size', Math.max(28, optimalSize * 1.1) + 'px');

                // 延迟更新位置，确保DOM更新完成
                setTimeout(() => {
                    this.updateGamePosition();
                    this.updateRightPanelPosition();
                }, 50);
            }

            // 更新游戏容器位置，确保不超出屏幕边界
            updateGamePosition() {
                const gameContainer = document.querySelector('.game-container');
                const gameContent = document.querySelector('.game-content');

                if (gameContainer && gameContent) {
                    const viewportHeight = window.innerHeight;
                    const gameHeight = gameContent.offsetHeight;

                    // 计算理想的top位置（35%）
                    let idealTop = viewportHeight * 0.35;

                    // 确保游戏区域上部不会超出屏幕（至少留20px边距）
                    const minTop = (gameHeight / 2) + 20;

                    // 确保游戏区域下部不会超出屏幕（至少留20px边距）
                    const maxTop = viewportHeight - (gameHeight / 2) - 20;

                    // 应用边界限制
                    const finalTop = Math.max(minTop, Math.min(idealTop, maxTop));

                    gameContainer.style.top = finalTop + 'px';
                    gameContainer.style.transform = 'translate(-50%, -50%)';
                }
            }

            // 更新右侧面板位置，使其紧贴游戏区域
            updateRightPanelPosition() {
                const gameContent = document.querySelector('.game-content');
                const rightPanel = document.querySelector('.right-panel');

                if (gameContent && rightPanel && window.innerWidth > 768) {
                    const gameRect = gameContent.getBoundingClientRect();
                    const panelWidth = rightPanel.offsetWidth;

                    // 计算面板应该在的位置（游戏区域右边 + 一点间距）
                    const leftPosition = gameRect.right + 20;

                    // 确保不超出屏幕右边界
                    const maxLeft = window.innerWidth - panelWidth - 20;
                    const finalLeft = Math.min(leftPosition, maxLeft);

                    rightPanel.style.left = finalLeft + 'px';
                    rightPanel.style.top = gameRect.top + 'px';
                    rightPanel.style.transform = 'none';

                    // 位置设置完成后显示面板
                    rightPanel.classList.add('positioned');
                } else if (rightPanel) {
                    // 在小屏幕上也要显示面板
                    rightPanel.classList.add('positioned');
                }
            }

            generateMines(firstClickRow, firstClickCol) {
                const positions = [];
                this.forEachCell((row, col) => {
                    if (Math.abs(row - firstClickRow) <= 1 && Math.abs(col - firstClickCol) <= 1) {
                        return;
                    }
                    positions.push([row, col]);
                });

                // Fisher-Yates洗牌
                for (let i = positions.length - 1; i > 0; i--) {
                    const j = Math.floor(Math.random() * (i + 1));
                    [positions[i], positions[j]] = [positions[j], positions[i]];
                }

                for (let i = 0; i < this.mineCount && i < positions.length; i++) {
                    const [row, col] = positions[i];
                    this.board[row][col] = -1;
                }

                this.calculateNumbers();
            }

            calculateNumbers() {
                this.forEachCell((row, col) => {
                    if (this.board[row][col] !== -1) {
                        let count = 0;
                        for (let dr = -1; dr <= 1; dr++) {
                            for (let dc = -1; dc <= 1; dc++) {
                                const newRow = row + dr;
                                const newCol = col + dc;
                                if (this.isValidCell(newRow, newCol) && this.board[newRow][newCol] === -1) {
                                    count++;
                                }
                            }
                        }
                        this.board[row][col] = count;
                    }
                });
            }

            isValidCell(row, col) {
                return row >= 0 && row < this.rows && col >= 0 && col < this.cols;
            }

            handleLeftClick(row, col, event) {
                event.preventDefault();
                if (this.isGameEnded()) return;
                if (this.flagged[row][col]) return;

                // 追踪移动次数
                this.moveCount++;

                if (this.firstClick) {
                    this.generateMines(row, col);
                    this.firstClick = false;
                    this.gameState = 'playing';
                    this.firstClickTime = Date.now();
                    this.startTimer();
                }

                this.revealCell(row, col);
                this.updateDisplay();
                this.checkGameState();
            }

            handleRightClick(row, col, event) {
                event.preventDefault();
                if (this.isGameEnded()) return;
                if (this.revealed[row][col]) return;

                // 追踪移动次数（标记也算移动）
                this.moveCount++;

                this.flagged[row][col] = !this.flagged[row][col];
                this.flagCount += this.flagged[row][col] ? 1 : -1;
                this.updateDisplay();
            }

            // 简化的双键快速挖掘
            handleMouseDown(row, col, event) {
                if (this.isGameEnded()) return;

                if (event.button === 0) {
                    this.mouseButtons.left = true;
                } else if (event.button === 2) {
                    this.mouseButtons.right = true;
                }

                if (this.mouseButtons.left && this.mouseButtons.right) {
                    this.quickDigCell = { row, col };
                    this.highlightQuickDigArea(row, col, true);
                    // 双键时小人变惊讶表情
                    this.getDomElement('smileyButton', 'smiley-button').textContent = '😮';
                }
            }

            handleMouseUp(row, col, event) {
                if (this.isGameEnded()) return;

                const wasQuickDig = this.mouseButtons.left && this.mouseButtons.right;

                if (wasQuickDig && this.quickDigCell &&
                    this.quickDigCell.row === row && this.quickDigCell.col === col) {
                    this.performQuickDig(row, col);
                } else if (event.button === 0 && !this.mouseButtons.right) {
                    this.handleLeftClick(row, col, event);
                } else if (event.button === 2 && !this.mouseButtons.left) {
                    this.handleRightClick(row, col, event);
                }

                // 重置状态
                if (event.button === 0) this.mouseButtons.left = false;
                if (event.button === 2) this.mouseButtons.right = false;

                if (this.quickDigCell) {
                    this.highlightQuickDigArea(this.quickDigCell.row, this.quickDigCell.col, false);
                    this.quickDigCell = null;
                    // 双键结束时恢复正常表情（如果游戏还在进行中）
                    if (this.gameState === 'playing' || this.gameState === 'ready') {
                        this.getDomElement('smileyButton', 'smiley-button').textContent = '😊';
                    }
                }
            }

            performQuickDig(row, col) {
                if (!this.revealed[row][col] || this.board[row][col] <= 0) return;

                let flaggedCount = 0;
                for (let dr = -1; dr <= 1; dr++) {
                    for (let dc = -1; dc <= 1; dc++) {
                        const newRow = row + dr;
                        const newCol = col + dc;
                        if (this.isValidCell(newRow, newCol) && this.flagged[newRow][newCol]) {
                            flaggedCount++;
                        }
                    }
                }

                if (flaggedCount === this.board[row][col]) {
                    for (let dr = -1; dr <= 1; dr++) {
                        for (let dc = -1; dc <= 1; dc++) {
                            const newRow = row + dr;
                            const newCol = col + dc;
                            if (this.isValidCell(newRow, newCol) &&
                                !this.revealed[newRow][newCol] &&
                                !this.flagged[newRow][newCol]) {
                                this.revealCell(newRow, newCol);
                            }
                        }
                    }
                    this.updateDisplay();
                    this.checkGameState();
                }
            }

            // 移动端双击快速挖掘处理
            handleMobileQuickDig(row, col, event) {
                if (this.isGameEnded()) return;
                if (!this.revealed[row][col] || this.board[row][col] <= 0) return;

                // 追踪移动次数
                this.moveCount++;

                // 显示高亮效果
                this.highlightQuickDigArea(row, col, true);

                // 短暂显示高亮后执行快速挖掘
                setTimeout(() => {
                    this.performQuickDig(row, col);
                    this.highlightQuickDigArea(row, col, false);
                }, 200);

                // 双击时小人变惊讶表情
                this.getDomElement('smileyButton', 'smiley-button').textContent = '😮';

                // 恢复表情
                setTimeout(() => {
                    if (this.gameState === 'playing' || this.gameState === 'ready') {
                        this.getDomElement('smileyButton', 'smiley-button').textContent = '😊';
                    }
                }, 300);
            }

            // 获取缓存的cell元素
            getCellElements() {
                if (!this.cellElements) {
                    this.cellElements = document.querySelectorAll('.cell');
                }
                return this.cellElements;
            }

            // 清除cell元素缓存（在重新创建游戏板时调用）
            clearCellCache() {
                this.cellElements = null;
            }

            // 检查游戏是否已结束
            isGameEnded() {
                return this.gameState === 'won' || this.gameState === 'lost';
            }

            // 格式化3位数字显示
            formatThreeDigits(num) {
                return Math.max(-99, Math.min(999, num)).toString().padStart(3, '0');
            }

            // 获取缓存的DOM元素
            getDomElement(key, id) {
                if (!this.domElements[key]) {
                    this.domElements[key] = document.getElementById(id);
                }
                return this.domElements[key];
            }

            // 遍历所有格子的辅助方法
            forEachCell(callback) {
                for (let row = 0; row < this.rows; row++) {
                    for (let col = 0; col < this.cols; col++) {
                        callback(row, col);
                    }
                }
            }

            highlightQuickDigArea(row, col, highlight) {
                if (!this.revealed[row][col] || this.board[row][col] <= 0) return;

                for (let dr = -1; dr <= 1; dr++) {
                    for (let dc = -1; dc <= 1; dc++) {
                        const newRow = row + dr;
                        const newCol = col + dc;
                        if (this.isValidCell(newRow, newCol)) {
                            const cellIndex = newRow * this.cols + newCol;
                            const cellElement = this.getCellElements()[cellIndex];
                            if (cellElement) {
                                if (highlight) {
                                    cellElement.classList.add('quick-dig-highlight');
                                } else {
                                    cellElement.classList.remove('quick-dig-highlight');
                                }
                            }
                        }
                    }
                }
            }

            revealCell(row, col) {
                if (!this.isValidCell(row, col) || this.revealed[row][col] || this.flagged[row][col]) {
                    return;
                }

                this.revealed[row][col] = true;

                if (this.board[row][col] === -1) {
                    this.gameState = 'lost';
                    this.revealAllMines();
                    return;
                }

                if (this.board[row][col] === 0) {
                    for (let dr = -1; dr <= 1; dr++) {
                        for (let dc = -1; dc <= 1; dc++) {
                            this.revealCell(row + dr, col + dc);
                        }
                    }
                }
            }

            revealAllMines() {
                this.forEachCell((row, col) => {
                    if (this.board[row][col] === -1) {
                        this.revealed[row][col] = true;
                    }
                });
            }

            checkGameState() {
                if (this.gameState === 'lost') {
                    this.getDomElement('smileyButton', 'smiley-button').textContent = '😵';
                    this.stopTimer();
                    setTimeout(() => {
                        showModal('游戏失败', '💣', '踩到地雷了！点击笑脸重新开始。');
                    }, 100);
                    return;
                }

                let unrevealedCount = 0;
                this.forEachCell((row, col) => {
                    if (!this.revealed[row][col] && this.board[row][col] !== -1) {
                        unrevealedCount++;
                    }
                });

                if (unrevealedCount === 0) {
                    this.gameState = 'won';
                    this.getDomElement('smileyButton', 'smiley-button').textContent = '😎';
                    this.stopTimer();

                    // 自动标记剩余地雷
                    this.forEachCell((row, col) => {
                        if (this.board[row][col] === -1 && !this.flagged[row][col]) {
                            this.flagged[row][col] = true;
                            this.flagCount++;
                        }
                    });

                    const elapsed = Math.floor((Date.now() - this.startTime) / 1000);
                    setTimeout(async () => {
                        const message = '用时：' + elapsed + '秒<br>难度：' + this.getDifficultyName() + '<br><br>恭喜！请输入用户名上传成绩：';
                        const username = await showModal('胜利！', '🎉', message, true, true);
                        if (username && username.trim()) {
                            uploadScore(username.trim(), elapsed, this.currentDifficulty, this);
                        }
                    }, 100);
                }
            }

            startTimer() {
                this.startTime = Date.now();
                this.timer = setInterval(() => {
                    const elapsed = Math.floor((Date.now() - this.startTime) / 1000);
                    this.getDomElement('timer', 'timer').textContent = this.formatThreeDigits(elapsed);
                }, 1000);
            }

            stopTimer() {
                if (this.timer) {
                    clearInterval(this.timer);
                    this.timer = null;
                }
            }

            getDifficultyName() {
                const names = {
                    beginner: '初级',
                    intermediate: '中级',
                    expert: '专家'
                };
                return names[this.currentDifficulty] || '未知';
            }

            updateDisplay() {
                const remainingMines = this.mineCount - this.flagCount;
                this.getDomElement('mineCounter', 'mine-counter').textContent = this.formatThreeDigits(remainingMines);

                const cells = this.getCellElements();
                cells.forEach((cell, index) => {
                    const row = Math.floor(index / this.cols);
                    const col = index % this.cols;

                    cell.className = 'cell';
                    cell.textContent = '';

                    if (this.flagged[row][col]) {
                        cell.classList.add('flagged');
                    } else if (this.revealed[row][col]) {
                        cell.classList.add('revealed');
                        if (this.board[row][col] === -1) {
                            cell.classList.add('mine');
                            cell.textContent = '💣';
                        } else if (this.board[row][col] > 0) {
                            cell.classList.add('number-' + this.board[row][col]);
                            cell.textContent = this.board[row][col];
                        }
                    }
                });
            }
        }

        // 全局变量
        let game = null;
        let currentLeaderboardDifficulty = 'beginner';
        let modalCallback = null;

        // 模态框函数
        function showModal(title, icon, message, showInput = false, showCancel = false) {
            document.getElementById('modal-title').textContent = title;
            document.getElementById('modal-icon').textContent = icon;
            document.getElementById('modal-message').innerHTML = message;

            const inputContainer = document.getElementById('modal-input-container');
            const cancelButton = document.getElementById('modal-cancel');
            const confirmButton = document.getElementById('modal-confirm');
            const input = document.getElementById('modal-input');

            if (showInput) {
                inputContainer.style.display = 'block';
                input.value = '';
                setTimeout(() => input.focus(), 100);
            } else {
                inputContainer.style.display = 'none';
            }

            if (showCancel) {
                cancelButton.style.display = 'inline-block';
                confirmButton.textContent = '确定';
            } else {
                cancelButton.style.display = 'none';
                confirmButton.textContent = '确定';
            }

            document.getElementById('game-modal').style.display = 'block';

            return new Promise((resolve) => {
                modalCallback = resolve;
            });
        }

        // 平滑更新模态框内容（不关闭模态框）
        function updateModal(title, icon, message) {
            document.getElementById('modal-title').textContent = title;
            document.getElementById('modal-icon').textContent = icon;
            document.getElementById('modal-message').innerHTML = message;

            // 隐藏输入框和取消按钮
            document.getElementById('modal-input-container').style.display = 'none';
            document.getElementById('modal-cancel').style.display = 'none';
            document.getElementById('modal-confirm').textContent = '确定';
        }

        function closeModal() {
            document.getElementById('game-modal').style.display = 'none';
            if (modalCallback) {
                modalCallback(null);
                modalCallback = null;
            }
        }

        function handleModalConfirm() {
            const input = document.getElementById('modal-input');
            const inputContainer = document.getElementById('modal-input-container');
            const cancelButton = document.getElementById('modal-cancel');

            let value;
            if (inputContainer.style.display !== 'none') {
                // 有输入框的情况
                value = input.value.trim();

                // 验证用户名长度（支持8个汉字或16个字符）
                if (value && [...value].length > 16) {
                    showModal('用户名过长', '⚠️', '用户名最多支持8个汉字或16个字符，请重新输入。');
                    return;
                }

                if (value && value.length === 0) {
                    showModal('用户名不能为空', '⚠️', '请输入有效的用户名。');
                    return;
                }
            } else if (cancelButton.style.display !== 'none') {
                // 有取消按钮的确认对话框
                value = true;
            } else {
                // 普通提示框
                value = true;
            }

            // 对于有输入框的情况（如上传成绩），不立即关闭模态框
            if (inputContainer.style.display === 'none') {
                // 普通提示框或确认框，正常关闭
                document.getElementById('game-modal').style.display = 'none';
            }
            // 注意：对于有输入框的情况，模态框会在uploadScore函数中保持显示并更新内容

            if (modalCallback) {
                modalCallback(value);
                modalCallback = null;
            }
        }

        function handleModalCancel() {
            document.getElementById('game-modal').style.display = 'none';
            if (modalCallback) {
                modalCallback(false);
                modalCallback = null;
            }
        }

        // 全局函数
        function setDifficulty(difficulty, event) {
            if (!game) return;

            document.querySelectorAll('.difficulty-button').forEach(btn => {
                btn.classList.remove('active');
            });
            if (event && event.target) {
                event.target.classList.add('active');
            }

            game.currentDifficulty = difficulty;
            game.initGame();
        }

        function newGame() {
            if (game) {
                game.initGame();
            }
        }

        function showHelp() {
            const helpMessage =
                '<div style="text-align: left; line-height: 1.6;">' +
                '<strong>🎯 游戏目标：</strong><br>' +
                '找出所有地雷而不踩到它们！<br><br>' +
                '<strong>🖱️ 桌面端操作：</strong><br>' +
                '• 左键：挖掘格子<br>' +
                '• 右键：标记地雷<br>' +
                '• 双键：在数字上同时按左右键快速挖掘<br><br>' +
                '<strong>📱 移动端操作：</strong><br>' +
                '• 点击：挖掘格子<br>' +
                '• 长按：标记地雷<br>' +
                '• 双击数字：快速挖掘周围格子<br><br>' +
                '<strong>🏆 难度选择：</strong><br>' +
                '• 初级：9×9，10个地雷<br>' +
                '• 中级：16×16，40个地雷<br>' +
                '• 专家：30×16，99个地雷<br><br>' +
                '<strong>💡 提示：</strong><br>' +
                '数字表示周围8个格子中地雷的数量<br>' +
                '快速挖掘需要先标记足够数量的地雷' +
                '</div>';
            showModal('怎么玩', '🎯', helpMessage);
        }

        function switchLeaderboard(difficulty, event) {
            currentLeaderboardDifficulty = difficulty;

            document.querySelectorAll('.tab-button').forEach(btn => {
                btn.classList.remove('active');
            });
            if (event && event.target) {
                event.target.classList.add('active');
            }

            loadLeaderboard(difficulty, true); // 切换时强制刷新
        }

        // 移动端排行榜功能
        function showMobileLeaderboard() {
            const modal = document.getElementById('mobile-leaderboard-modal');
            if (modal) {
                modal.classList.add('show');
                // 加载当前难度的排行榜数据到移动端模态框
                loadMobileLeaderboard(currentLeaderboardDifficulty, true);
            }
        }

        function hideMobileLeaderboard() {
            const modal = document.getElementById('mobile-leaderboard-modal');
            if (modal) {
                modal.classList.remove('show');
            }
        }

        function switchMobileLeaderboard(difficulty, event) {
            currentLeaderboardDifficulty = difficulty;

            document.querySelectorAll('.mobile-tab-button').forEach(btn => {
                btn.classList.remove('active');
            });
            if (event && event.target) {
                event.target.classList.add('active');
            }

            loadMobileLeaderboard(difficulty, true); // 切换时强制刷新
        }

        async function loadMobileLeaderboard(difficulty, forceRefresh = false) {
            try {
                // 添加缓存破坏参数以确保获取最新数据
                const url = '/api/leaderboard/' + difficulty + (forceRefresh ? '?t=' + Date.now() + '&r=' + Math.random() : '');
                const response = await fetch(url, {
                    method: 'GET',
                    headers: {
                        'Cache-Control': 'no-cache, no-store, must-revalidate',
                        'Pragma': 'no-cache',
                        'Expires': '0'
                    }
                });
                const result = await response.json();

                const listElement = document.getElementById('mobile-leaderboard-list');

                // 清空现有内容
                listElement.innerHTML = '';

                if (result.success && result.data.length > 0) {
                    // 使用安全的DOM操作替代innerHTML
                    result.data.forEach((record, index) => {
                        const item = createLeaderboardItem(record, index);
                        listElement.appendChild(item);
                    });
                } else {
                    // 安全地创建"暂无记录"消息
                    const emptyMessage = createElement('div', '', '暂无记录', {
                        textAlign: 'center',
                        padding: '20px',
                        color: '#666'
                    });
                    listElement.appendChild(emptyMessage);
                }
            } catch (error) {
                // 安全地创建错误消息
                const listElement = document.getElementById('mobile-leaderboard-list');
                listElement.innerHTML = '';
                const errorMessage = createElement('div', '', '加载失败', {
                    textAlign: 'center',
                    padding: '20px',
                    color: '#d00'
                });
                listElement.appendChild(errorMessage);
            }
        }

        // 定期刷新排行榜以确保实时性
        function startLeaderboardAutoRefresh() {
            setInterval(() => {
                // 每30秒自动刷新当前显示的排行榜
                loadLeaderboard(currentLeaderboardDifficulty, true);
            }, 30000); // 30秒间隔
        }

        // 注释：已移除错误的 updateLeaderboardDisplay 函数
        // 该函数试图更新不存在的 #leaderboard-table tbody 元素
        // 现在直接在 uploadScore 中正确更新 #leaderboard-list

        // DOM元素创建辅助函数
        function createElement(tag, className, textContent, styles = {}) {
            const element = document.createElement(tag);
            if (className) element.className = className;
            if (textContent) element.textContent = textContent;
            Object.assign(element.style, styles);
            return element;
        }

        // 安全的排行榜项创建函数 - 防止XSS攻击
        function createLeaderboardItem(record, index) {
            const item = createElement('div', 'leaderboard-item');
            const rank = createElement('div', 'leaderboard-rank', index + 1);
            const username = createElement('div', 'leaderboard-username', record.username);
            const time = createElement('div', 'leaderboard-time', record.time + 's');

            item.appendChild(rank);
            item.appendChild(username);
            item.appendChild(time);
            return item;
        }

        async function loadLeaderboard(difficulty, forceRefresh = false) {
            try {
                // 添加缓存破坏参数以确保获取最新数据
                const url = '/api/leaderboard/' + difficulty + (forceRefresh ? '?t=' + Date.now() + '&r=' + Math.random() : '');
                const response = await fetch(url, {
                    method: 'GET',
                    headers: {
                        'Cache-Control': 'no-cache, no-store, must-revalidate',
                        'Pragma': 'no-cache',
                        'Expires': '0'
                    }
                });
                const result = await response.json();

                const listElement = document.getElementById('leaderboard-list');

                // 清空现有内容
                listElement.innerHTML = '';

                if (result.success && result.data.length > 0) {
                    // 使用安全的DOM操作替代innerHTML
                    result.data.forEach((record, index) => {
                        const item = createLeaderboardItem(record, index);
                        listElement.appendChild(item);
                    });
                } else {
                    // 安全地创建"暂无记录"消息
                    const emptyMessage = createElement('div', '', '暂无记录', {
                        textAlign: 'center',
                        padding: '20px',
                        color: '#666'
                    });
                    listElement.appendChild(emptyMessage);
                }
            } catch (error) {
                // 安全地创建错误消息
                const listElement = document.getElementById('leaderboard-list');
                listElement.innerHTML = '';
                const errorMessage = createElement('div', '', '加载失败', {
                    textAlign: 'center',
                    padding: '20px',
                    color: '#d00'
                });
                listElement.appendChild(errorMessage);
            }
        }

        async function uploadScore(username, time, difficulty, gameInstance) {
            try {
                // 确保模态框显示并立即更新为"正在提交"状态
                document.getElementById('game-modal').style.display = 'block';
                updateModal('正在提交', '⏳', '正在上传您的成绩，请稍候...');

                // 首先获取当前排行榜数据，检查用户是否已有记录
                const getResponse = await fetch('/api/leaderboard/' + difficulty);
                const getResult = await getResponse.json();

                let existingRecord = null;
                let isNewRecord = false;
                let rankImprovement = '';

                if (getResult.success && getResult.data.length > 0) {
                    // 查找用户的现有记录
                    existingRecord = getResult.data.find(record => record.username === username.trim());

                    if (existingRecord) {
                        // 用户已有记录，比较成绩
                        if (time < existingRecord.time) {
                            // 新成绩更好
                            const improvement = existingRecord.time - time;
                            isNewRecord = true;
                            rankImprovement = '恭喜！您的成绩提升了 ' + improvement + ' 秒！';
                        } else if (time > existingRecord.time) {
                            // 新成绩更差，直接提醒并取消上传
                            const decline = time - existingRecord.time;
                            showModal(
                                '成绩未达最佳',
                                '📊',
                                '您的当前成绩：' + time + '秒<br>您的最佳成绩：' + existingRecord.time + '秒<br><br>新成绩比最佳成绩慢了 ' + decline + ' 秒，未上传到排行榜。<br><br>继续努力，争取打破个人纪录！'
                            );
                            return; // 直接取消上传
                        } else {
                            // 成绩相同
                            showModal('成绩相同', 'ℹ️', '您的成绩与之前的最佳成绩相同（' + time + '秒），无需重复上传。');
                            return;
                        }
                    }
                }

                // 收集游戏数据用于服务端验证
                const gameData = {
                    difficulty: difficulty,
                    time: time,
                    moves: gameInstance.moveCount,
                    gameId: gameInstance.gameId,
                    timestamp: gameInstance.gameStartTime,
                    boardSize: {
                        width: gameInstance.cols,
                        height: gameInstance.rows
                    },
                    mineCount: gameInstance.mineCount,
                    gameEndTime: Date.now(),
                    firstClickTime: gameInstance.firstClickTime,
                    gameState: 'won'
                };

                // 上传成绩（包含完整游戏数据用于验证）
                const response = await fetch('/api/leaderboard/' + difficulty, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Accept': 'application/json'
                    },
                    body: JSON.stringify({ username, time, gameData })
                });

                const result = await response.json();
                if (result.success) {
                    // 查找用户在新排行榜中的排名
                    const userRank = result.data.findIndex(record => record.username === username.trim()) + 1;

                    let successMessage = '';
                    let modalTitle = '';
                    let modalIcon = '';

                    if (userRank > 0 && userRank <= 20) {
                        // 用户上榜了
                        modalTitle = '🎉 恭喜上榜！';
                        modalIcon = '🏆';

                        if (isNewRecord && existingRecord) {
                            // 打破个人纪录并上榜
                            const improvement = existingRecord.time - time;
                            successMessage = '🎉 新纪录并成功上榜！<br><br>' +
                                           '旧成绩：' + existingRecord.time + '秒<br>' +
                                           '新成绩：' + time + '秒<br>' +
                                           '提升：' + improvement + '秒<br><br>' +
                                           '🏆 当前排名：第 ' + userRank + ' 名';
                        } else if (!existingRecord) {
                            // 首次上传并上榜
                            successMessage = '🎊 首次上传即上榜！<br><br>' +
                                           '您的成绩：' + time + '秒<br>' +
                                           '🏆 当前排名：第 ' + userRank + ' 名<br><br>' +
                                           '欢迎加入排行榜！';
                        } else {
                            // 其他上榜情况
                            successMessage = '🎉 成功上榜！<br><br>' +
                                           '您的成绩：' + time + '秒<br>' +
                                           '🏆 当前排名：第 ' + userRank + ' 名';
                        }
                    } else {
                        // 用户没有上榜（排名在20名之外或未找到）
                        modalTitle = '📊 成绩已记录';
                        modalIcon = '📈';

                        if (isNewRecord && existingRecord) {
                            // 打破个人纪录但未上榜
                            const improvement = existingRecord.time - time;
                            successMessage = '🎯 个人新纪录！<br><br>' +
                                           '旧成绩：' + existingRecord.time + '秒<br>' +
                                           '新成绩：' + time + '秒<br>' +
                                           '提升：' + improvement + '秒<br><br>' +
                                           '💪 继续努力，争取进入前20名排行榜！';
                        } else if (!existingRecord) {
                            // 首次上传但未上榜
                            successMessage = '📝 首次成绩已记录！<br><br>' +
                                           '您的成绩：' + time + '秒<br><br>' +
                                           '💪 继续练习，争取进入前20名排行榜！<br>' +
                                           '目前需要达到更好的成绩才能上榜。';
                        } else {
                            // 其他未上榜情况
                            successMessage = '📊 成绩已更新！<br><br>' +
                                           '您的成绩：' + time + '秒<br><br>' +
                                           '💪 继续努力，争取进入前20名排行榜！';
                        }
                    }

                    // 立即更新模态框内容
                    updateModal(modalTitle, modalIcon, successMessage);

                    // 立即更新排行榜显示（无论是否上榜都要刷新）
                    // 如果当前显示的难度与上传的难度不同，先切换到对应难度
                    if (currentLeaderboardDifficulty !== difficulty) {
                        currentLeaderboardDifficulty = difficulty;
                        // 更新排行榜标签页
                        document.querySelectorAll('.tab-button').forEach(btn => {
                            btn.classList.remove('active');
                        });
                        // 根据难度激活对应的标签
                        const difficultyMap = {
                            'beginner': '初级',
                            'intermediate': '中级',
                            'expert': '专家'
                        };
                        const targetText = difficultyMap[difficulty];
                        document.querySelectorAll('.tab-button').forEach(btn => {
                            if (btn.textContent.trim() === targetText) {
                                btn.classList.add('active');
                            }
                        });
                    }

                    // 使用正确的函数来更新排行榜显示，直接使用服务器返回的最新数据
                    const listElement = document.getElementById('leaderboard-list');
                    if (listElement && result.data) {
                        // 清空现有内容
                        listElement.innerHTML = '';

                        if (result.data.length > 0) {
                            // 使用安全的DOM操作更新排行榜
                            result.data.forEach((record, index) => {
                                const item = createLeaderboardItem(record, index);
                                listElement.appendChild(item);
                            });
                        } else {
                            // 安全地创建"暂无记录"消息
                            const emptyMessage = document.createElement('div');
                            emptyMessage.style.textAlign = 'center';
                            emptyMessage.style.padding = '20px';
                            emptyMessage.style.color = '#666';
                            emptyMessage.textContent = '暂无记录';
                            listElement.appendChild(emptyMessage);
                        }
                    }

                    // 🔥 关键修复：立即强制刷新排行榜，确保显示最新数据
                    // 移除延迟刷新，避免与直接更新产生冲突
                    loadLeaderboard(difficulty, true);

                } else {
                    // 正确解析错误对象并显示
                    let errorMsg = '未知错误';
                    if (result.error) {
                        if (typeof result.error === 'string') {
                            errorMsg = result.error;
                        } else if (result.error.message) {
                            errorMsg = result.error.message;
                        } else if (result.error.code) {
                            errorMsg = result.error.code;
                        }
                    }
                    updateModal('上传失败', '❌', '上传失败：' + errorMsg);
                }
            } catch (error) {
                console.error('Upload error:', error);
                let errorMessage = '网络连接错误';

                if (error.name === 'TypeError' && error.message.includes('fetch')) {
                    errorMessage = '网络连接失败，请检查网络状态';
                } else if (error.message) {
                    errorMessage = error.message;
                }

                updateModal('上传失败', '❌', '上传失败：' + errorMessage);
            }
        }

        // 初始化
        window.addEventListener('DOMContentLoaded', () => {
            // 全局禁用右键菜单 - 多重保护
            document.body.addEventListener('contextmenu', (e) => {
                e.preventDefault();
                e.stopPropagation();
                return false;
            });

            // 禁用选择文本（可选，防止意外选择）
            document.body.style.userSelect = 'none';
            document.body.style.webkitUserSelect = 'none';
            document.body.style.mozUserSelect = 'none';
            document.body.style.msUserSelect = 'none';

            game = new MinesweeperGame();
            game.initGame();
            loadLeaderboard('beginner', true); // 初始加载时强制刷新

            // 启动排行榜自动刷新
            startLeaderboardAutoRefresh();

            // 确保右侧面板在初始化后显示
            setTimeout(() => {
                if (game) {
                    game.updateRightPanelPosition();
                }
            }, 200);

            // 窗口大小变化监听
            window.addEventListener('resize', () => {
                if (game) {
                    game.calculateCellSize();
                    // 延迟更新位置，确保DOM已更新
                    setTimeout(() => {
                        game.updateGamePosition();
                        game.updateRightPanelPosition();
                    }, 100);
                }
            });

            // 全局鼠标事件监听（清理双键状态）
            document.addEventListener('mouseup', (e) => {
                if (game && !e.target.closest('.cell')) {
                    game.mouseButtons.left = false;
                    game.mouseButtons.right = false;
                    if (game.quickDigCell) {
                        game.highlightQuickDigArea(game.quickDigCell.row, game.quickDigCell.col, false);
                        game.quickDigCell = null;
                        // 恢复正常表情（如果游戏还在进行中）
                        if (game.gameState === 'playing' || game.gameState === 'ready') {
                            document.getElementById('smiley-button').textContent = '😊';
                        }
                    }
                }
            });

            // 全局禁用右键菜单，防止浏览器接管
            document.addEventListener('contextmenu', (e) => {
                e.preventDefault();
                return false;
            });

            // 只防止长按菜单，允许游戏区域的缩放和拖动
            // 注意：我们移除了对游戏区域缩放和拖动的阻止，现在允许这些手势

            // 绑定所有按钮事件（修复 CSP 阻止内联 onclick 的问题）

            // 1. 笑脸按钮事件
            const smileyButton = document.getElementById('smiley-button');
            if (smileyButton) {
                smileyButton.addEventListener('click', newGame);
            }

            // 2. 帮助按钮事件
            const helpButton = document.getElementById('help-button');
            if (helpButton) {
                helpButton.addEventListener('click', showHelp);
            }

            // 3. 难度选择按钮事件
            document.querySelectorAll('.difficulty-button').forEach(button => {
                button.addEventListener('click', (e) => {
                    const difficulty = e.target.getAttribute('data-difficulty');
                    if (difficulty) {
                        setDifficulty(difficulty, e);
                    }
                });
            });

            // 4. 排行榜标签页事件
            document.querySelectorAll('.tab-button').forEach(button => {
                button.addEventListener('click', (e) => {
                    const difficulty = e.target.getAttribute('data-difficulty');
                    if (difficulty) {
                        switchLeaderboard(difficulty, e);
                    }
                });
            });

            // 5. 模态框按钮事件
            const modalConfirm = document.getElementById('modal-confirm');
            const modalCancel = document.getElementById('modal-cancel');

            if (modalConfirm) {
                modalConfirm.addEventListener('click', handleModalConfirm);
            }

            if (modalCancel) {
                modalCancel.addEventListener('click', handleModalCancel);
            }

            // 6. 移动端排行榜按钮事件
            const mobileLeaderboardButton = document.getElementById('mobile-leaderboard-button');
            if (mobileLeaderboardButton) {
                mobileLeaderboardButton.addEventListener('click', showMobileLeaderboard);
            }

            // 7. 移动端排行榜关闭按钮事件
            const mobileLeaderboardClose = document.getElementById('mobile-leaderboard-close');
            if (mobileLeaderboardClose) {
                mobileLeaderboardClose.addEventListener('click', hideMobileLeaderboard);
            }

            // 8. 移动端排行榜标签页事件
            document.querySelectorAll('.mobile-tab-button').forEach(button => {
                button.addEventListener('click', (e) => {
                    const difficulty = e.target.getAttribute('data-difficulty');
                    if (difficulty) {
                        switchMobileLeaderboard(difficulty, e);
                    }
                });
            });

            // 9. 移动端排行榜模态框背景点击关闭
            const mobileLeaderboardModal = document.getElementById('mobile-leaderboard-modal');
            if (mobileLeaderboardModal) {
                mobileLeaderboardModal.addEventListener('click', (e) => {
                    if (e.target === mobileLeaderboardModal) {
                        hideMobileLeaderboard();
                    }
                });
            }

        });
    </script>
</body>
</html>`;
}
