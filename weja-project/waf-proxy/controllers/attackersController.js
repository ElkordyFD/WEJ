const mongoose = require('mongoose');
const Log = require('../models/Log');
const { isInMemory, getInMemoryLogs } = require('../database/connection');
const { getGeoLocation } = require('../services/geolocation');
const blacklistService = require('../services/blacklist');

// Get top attackers (for Attacker Map)
const getTopAttackers = async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 10;
        let topAttackers;

        if (isInMemory() || mongoose.connection.readyState !== 1) {
            // Aggregate from in-memory logs
            const ipMap = {};
            const memoryLogs = getInMemoryLogs();
            memoryLogs.filter(l => l.blocked).forEach(log => {
                const ip = log.sourceIp;
                if (!ipMap[ip]) {
                    ipMap[ip] = {
                        ip: ip,
                        attackCount: 0,
                        lastAttack: log.timestamp,
                        attackTypes: {},
                        geo: getGeoLocation(ip),
                        isBlacklisted: blacklistService.isBlacklisted(ip)
                    };
                }
                ipMap[ip].attackCount++;
                ipMap[ip].attackTypes[log.attackType] = (ipMap[ip].attackTypes[log.attackType] || 0) + 1;
                if (new Date(log.timestamp) > new Date(ipMap[ip].lastAttack)) {
                    ipMap[ip].lastAttack = log.timestamp;
                }
            });

            topAttackers = Object.values(ipMap)
                .map(attacker => ({
                    ...attacker,
                    attackTypes: Object.entries(attacker.attackTypes)
                        .map(([type, count]) => ({ type, count }))
                        .sort((a, b) => b.count - a.count)
                }))
                .sort((a, b) => b.attackCount - a.attackCount)
                .slice(0, limit);
        } else {
            // Aggregate from MongoDB
            const attackersAgg = await Log.aggregate([
                { $match: { blocked: true } },
                {
                    $group: {
                        _id: '$sourceIp',
                        attackCount: { $sum: 1 },
                        lastAttack: { $max: '$timestamp' },
                        attackTypes: { $push: '$attackType' }
                    }
                },
                { $sort: { attackCount: -1 } },
                { $limit: limit }
            ]);

            topAttackers = attackersAgg.map(a => {
                const typeCounts = {};
                a.attackTypes.forEach(t => { typeCounts[t] = (typeCounts[t] || 0) + 1; });

                return {
                    ip: a._id,
                    attackCount: a.attackCount,
                    lastAttack: a.lastAttack,
                    attackTypes: Object.entries(typeCounts)
                        .map(([type, count]) => ({ type, count }))
                        .sort((a, b) => b.count - a.count),
                    geo: getGeoLocation(a._id),
                    isBlacklisted: blacklistService.isBlacklisted(a._id)
                };
            });
        }

        res.json({
            count: topAttackers.length,
            attackers: topAttackers
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

module.exports = {
    getTopAttackers
};
