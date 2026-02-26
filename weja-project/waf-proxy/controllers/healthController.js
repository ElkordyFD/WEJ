const mongoose = require('mongoose');
const axios = require('axios');
const CONFIG = require('../config');
const { isInMemory } = require('../database/connection');
const { ipBlacklist } = require('../services/blacklist');

// Health check
const getHealth = async (req, res) => {
    try {
        // Check AI Engine
        const aiHealth = await axios.get(`${CONFIG.AI_ENGINE_URL}/health`, { timeout: 2000 })
            .then(() => 'healthy')
            .catch(() => 'unhealthy');

        // Check MongoDB
        const dbHealth = mongoose.connection.readyState === 1 ? 'healthy' : 'unavailable (using memory)';

        res.json({
            waf: 'healthy',
            aiEngine: aiHealth,
            database: dbHealth,
            storage: isInMemory() ? 'memory' : 'mongodb',
            target: CONFIG.TARGET_URL,
            blacklistedIPs: ipBlacklist.size
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

module.exports = {
    getHealth
};
