const axios = require('axios');
const http = require('http');
const https = require('https');
const CONFIG = require('../config');

const aiClient = axios.create({
    baseURL: CONFIG.AI_ENGINE_URL,
    timeout: 1500,
    httpAgent: new http.Agent({ keepAlive: true }),
    httpsAgent: new https.Agent({ keepAlive: true })
});

module.exports = aiClient;
