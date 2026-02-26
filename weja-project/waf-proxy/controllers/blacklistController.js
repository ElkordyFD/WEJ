const CONFIG = require('../config');
const blacklistService = require('../services/blacklist');

// Get all blacklisted IPs
const getBlacklist = (req, res) => {
    const blacklist = [];
    blacklistService.ipBlacklist.forEach((entry, ip) => {
        // Check if still valid
        if (Date.now() - entry.blockedAt <= CONFIG.BLACKLIST_DURATION) {
            blacklist.push({
                ip: ip,
                blockedAt: new Date(entry.blockedAt).toISOString(),
                reason: entry.reason,
                autoBlocked: entry.autoBlocked,
                geo: entry.geo,
                remainingSeconds: Math.ceil((CONFIG.BLACKLIST_DURATION - (Date.now() - entry.blockedAt)) / 1000)
            });
        }
    });

    res.json({
        count: blacklist.length,
        blacklist: blacklist.sort((a, b) => b.blockedAt - a.blockedAt)
    });
};

// Add IP to blacklist manually
const addBlacklist = (req, res) => {
    const { ip, reason } = req.body;

    if (!ip) {
        return res.status(400).json({ error: 'IP address is required' });
    }

    if (blacklistService.isBlacklisted(ip)) {
        return res.status(409).json({ error: 'IP is already blacklisted' });
    }

    blacklistService.addToBlacklist(ip, reason || 'Manually added', false);

    res.json({
        success: true,
        message: `IP ${ip} added to blacklist`,
        expiresIn: CONFIG.BLACKLIST_DURATION / 1000 + ' seconds'
    });
};

// Remove IP from blacklist
const removeBlacklist = (req, res) => {
    const ip = req.params.ip;

    if (!blacklistService.ipBlacklist.has(ip)) {
        return res.status(404).json({ error: 'IP not found in blacklist' });
    }

    blacklistService.ipBlacklist.delete(ip);
    blacklistService.ipAttackCount.delete(ip);
    console.log(`✅ IP ${ip} removed from blacklist`);

    res.json({
        success: true,
        message: `IP ${ip} removed from blacklist`
    });
};

module.exports = {
    getBlacklist,
    addBlacklist,
    removeBlacklist
};
