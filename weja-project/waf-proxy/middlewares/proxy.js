const http = require('http');
const CONFIG = require('../config');

const proxyMiddleware = (req, res) => {
    const targetUrl = new URL(req.originalUrl, CONFIG.TARGET_URL);

    // Copy headers but override host for the target
    const headers = { ...req.headers, host: targetUrl.host };

    const proxyReq = http.request(
        {
            hostname: targetUrl.hostname,
            port: targetUrl.port,
            path: targetUrl.pathname + targetUrl.search,
            method: req.method,
            headers: headers,
            timeout: 30000
        },
        (proxyRes) => {
            // Forward status + headers from target back to client
            res.writeHead(proxyRes.statusCode, proxyRes.headers);
            proxyRes.pipe(res);
        }
    );

    proxyReq.on('error', (err) => {
        console.error('🔥 Proxy error:', err.message);
        if (!res.headersSent) {
            res.status(502).json({ error: 'Bad Gateway', message: err.message });
        }
    });

    proxyReq.on('timeout', () => {
        proxyReq.destroy();
        if (!res.headersSent) {
            res.status(504).json({ error: 'Gateway Timeout' });
        }
    });

    // Re-attach the body that Express already consumed & parsed
    if (req.body && Object.keys(req.body).length > 0 && req.method !== 'GET') {
        const contentType = req.headers['content-type'] || 'application/json';
        let bodyData;

        if (contentType.includes('application/x-www-form-urlencoded')) {
            bodyData = new URLSearchParams(req.body).toString();
        } else {
            bodyData = JSON.stringify(req.body);
        }

        proxyReq.setHeader('Content-Length', Buffer.byteLength(bodyData));
        proxyReq.write(bodyData);
    }

    proxyReq.end();
};

module.exports = proxyMiddleware;
