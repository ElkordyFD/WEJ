const mongoose = require('mongoose');
const Log = require('../models/Log');
const CONFIG = require('../config');
const { isInMemory, getInMemoryLogs, updateInMemoryLogs } = require('./connection');

// Helper function to save log
const saveLog = async (logData) => {
    if (isInMemory() || mongoose.connection.readyState !== 1) {
        const memLog = {
            _id: Date.now().toString(36) + Math.random().toString(36).substr(2),
            ...logData,
            timestamp: new Date(),
            createdAt: new Date(),
            updatedAt: new Date()
        };
        const logs = getInMemoryLogs();
        logs.unshift(memLog);
        if (logs.length > CONFIG.MAX_MEMORY_LOGS) {
            logs.pop();
        }
        updateInMemoryLogs(logs);
        return memLog;
    } else {
        const logEntry = new Log(logData);
        await logEntry.save();
        return logEntry;
    }
};

module.exports = {
    saveLog
};
