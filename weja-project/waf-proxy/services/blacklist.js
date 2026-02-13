const CONFIG = require('../config');
const { getGeoLocation } = require('./geolocation');

// ============ IP BLACKLIST SYSTEM ============
const ipBlacklist = new Map(); // IP -> { blockedAt, reason, autoBlocked }
const ipAttackCount = new Map(); // IP -> count of blocked requests

// Check if IP is blacklisted
const isBlacklisted = (ip) => {
    const entry = ipBlacklist.get(ip);
    if (!entry) return false;

    // Check if blacklist has expired
    if (Date.now() - entry.blockedAt > CONFIG.BLACKLIST_DURATION) {
        ipBlacklist.delete(ip);
        return false;
    }
    return true;
};

// Add IP to blacklist
const addToBlacklist = (ip, reason, autoBlocked = false) => {
    ipBlacklist.set(ip, {
        blockedAt: Date.now(),
        reason: reason,
        autoBlocked: autoBlocked,
        geo: getGeoLocation(ip)
    });
    console.log(`🚫 IP ${ip} added to blacklist: ${reason}`);
};

// Track attack attempts and auto-blacklist
const trackAttack = (ip, attackType) => {
    const count = (ipAttackCount.get(ip) || 0) + 1;
    ipAttackCount.set(ip, count);

    if (count >= CONFIG.BLACKLIST_THRESHOLD && !isBlacklisted(ip)) {
        addToBlacklist(ip, `Auto-blocked after ${count} attacks (${attackType})`, true);
    }
};

module.exports = {
    ipBlacklist,
    ipAttackCount,
    isBlacklisted,
    addToBlacklist,
    trackAttack
};
