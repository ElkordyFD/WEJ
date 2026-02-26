const mongoose = require('mongoose');
const Log = require('../models/Log');
const { isInMemory, getInMemoryLogs } = require('../database/connection');

// Get all logs (paginated)
const getLogs = async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 50;
        const skip = (page - 1) * limit;

        let logs, total;

        if (isInMemory() || mongoose.connection.readyState !== 1) {
            const memoryLogs = getInMemoryLogs();
            total = memoryLogs.length;
            logs = memoryLogs.slice(skip, skip + limit);
        } else {
            logs = await Log.find()
                .sort({ timestamp: -1 })
                .skip(skip)
                .limit(limit);
            total = await Log.countDocuments();
        }

        res.json({
            logs,
            pagination: {
                page,
                limit,
                total,
                pages: Math.ceil(total / limit)
            },
            storage: isInMemory() ? 'memory' : 'mongodb'
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

// Get attack statistics
const getStats = async (req, res) => {
    try {
        let totalRequests, blockedRequests, attackTypes, hourlyTraffic;

        if (isInMemory() || mongoose.connection.readyState !== 1) {
            const memoryLogs = getInMemoryLogs();
            totalRequests = memoryLogs.length;
            blockedRequests = memoryLogs.filter(l => l.blocked).length;

            // Attack type breakdown
            const typeMap = {};
            memoryLogs.filter(l => l.blocked).forEach(l => {
                typeMap[l.attackType] = (typeMap[l.attackType] || 0) + 1;
            });
            attackTypes = Object.entries(typeMap)
                .map(([type, count]) => ({ type, count }))
                .sort((a, b) => b.count - a.count);

            hourlyTraffic = [];
        } else {
            totalRequests = await Log.countDocuments();
            blockedRequests = await Log.countDocuments({ blocked: true });

            const attackTypesAgg = await Log.aggregate([
                { $match: { blocked: true } },
                { $group: { _id: '$attackType', count: { $sum: 1 } } },
                { $sort: { count: -1 } }
            ]);
            attackTypes = attackTypesAgg.map(t => ({ type: t._id, count: t.count }));

            hourlyTraffic = await Log.aggregate([
                {
                    $match: {
                        timestamp: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
                    }
                },
                {
                    $group: {
                        _id: {
                            hour: { $hour: '$timestamp' },
                            blocked: '$blocked'
                        },
                        count: { $sum: 1 }
                    }
                },
                { $sort: { '_id.hour': 1 } }
            ]);
        }

        const allowedRequests = totalRequests - blockedRequests;

        res.json({
            summary: {
                total: totalRequests,
                blocked: blockedRequests,
                allowed: allowedRequests,
                blockRate: totalRequests > 0 ? ((blockedRequests / totalRequests) * 100).toFixed(2) : 0
            },
            attackTypes,
            hourlyTraffic,
            storage: isInMemory() ? 'memory' : 'mongodb'
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

module.exports = {
    getLogs,
    getStats
};
