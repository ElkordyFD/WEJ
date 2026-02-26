// Simulated geolocation data for demo purposes
const SIMULATED_GEOLOCATIONS = {
    '127.0.0.1': { country: 'Local', city: 'Localhost', lat: 0, lon: 0 },
    '::1': { country: 'Local', city: 'Localhost', lat: 0, lon: 0 },
    '192.168.': { country: 'Private Network', city: 'LAN', lat: 0, lon: 0 },
    '10.': { country: 'Private Network', city: 'LAN', lat: 0, lon: 0 },
    'default': [
        { country: 'United States', city: 'New York', lat: 40.7128, lon: -74.0060 },
        { country: 'Russia', city: 'Moscow', lat: 55.7558, lon: 37.6173 },
        { country: 'China', city: 'Beijing', lat: 39.9042, lon: 116.4074 },
        { country: 'Germany', city: 'Berlin', lat: 52.5200, lon: 13.4050 },
        { country: 'Brazil', city: 'São Paulo', lat: -23.5505, lon: -46.6333 },
        { country: 'India', city: 'Mumbai', lat: 19.0760, lon: 72.8777 },
        { country: 'Nigeria', city: 'Lagos', lat: 6.5244, lon: 3.3792 },
        { country: 'Australia', city: 'Sydney', lat: -33.8688, lon: 151.2093 }
    ]
};

// Get simulated geolocation for an IP
const getGeoLocation = (ip) => {
    if (ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1') {
        return SIMULATED_GEOLOCATIONS['127.0.0.1'];
    }
    if (ip.startsWith('192.168.') || ip.startsWith('::ffff:192.168.')) {
        return SIMULATED_GEOLOCATIONS['192.168.'];
    }
    if (ip.startsWith('10.') || ip.startsWith('::ffff:10.')) {
        return SIMULATED_GEOLOCATIONS['10.'];
    }
    // Return random location for other IPs (consistent per IP using hash)
    const hash = ip.split('').reduce((a, b) => a + b.charCodeAt(0), 0);
    const locations = SIMULATED_GEOLOCATIONS['default'];
    return locations[hash % locations.length];
};

module.exports = {
    getGeoLocation,
    SIMULATED_GEOLOCATIONS
};
