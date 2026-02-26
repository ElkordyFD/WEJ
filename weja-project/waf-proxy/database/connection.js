const mongoose = require('mongoose');
const CONFIG = require('../config');

let useInMemory = false;
let inMemoryLogs = [];

// ============ DATABASE CONNECTION ============
const connectDB = async () => {
    try {
        await mongoose.connect(CONFIG.MONGODB_URI, {
            serverSelectionTimeoutMS: 3000,
            connectTimeoutMS: 3000
        });
        console.log('📦 Connected to MongoDB');
        useInMemory = false;
        return true;
    } catch (err) {
        console.warn('⚠️  MongoDB unavailable, using in-memory storage');
        console.warn('   To enable MongoDB: brew services start mongodb-community');
        useInMemory = true;
        return false;
    }
};

const getInMemoryLogs = () => inMemoryLogs;
const isInMemory = () => useInMemory;

// Update in-memory logs (for unshift/pop operations)
const updateInMemoryLogs = (logs) => {
    inMemoryLogs = logs;
};

module.exports = {
    connectDB,
    getInMemoryLogs,
    isInMemory,
    updateInMemoryLogs
};
