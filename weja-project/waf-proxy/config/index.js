// ============ CONFIGURATION ============
const CONFIG = {
    PORT: process.env.PORT || 3000,
    AI_ENGINE_URL: process.env.AI_ENGINE_URL || 'http://localhost:5000',
    TARGET_URL: process.env.TARGET_URL || 'http://localhost:4000',
    MONGODB_URI: process.env.MONGODB_URI || 'mongodb://localhost:27017/weja_waf',

    // Blacklist configuration
    BLACKLIST_THRESHOLD: 3, // Auto-blacklist after 3 blocked requests
    BLACKLIST_DURATION: 60 * 60 * 1000, // 1 hour blacklist duration

    // Logging configuration
    MAX_MEMORY_LOGS: 1000
};

module.exports = CONFIG;
