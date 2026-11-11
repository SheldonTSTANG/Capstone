const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'fallback_jwt_key_2026';

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Format: "Bearer <TOKEN>"

    if (!token) {
        return res.status(401).json({ error: 'Access denied: No token provided.' });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired session token.' });
        }
        req.user = decoded; // Contains: { userId, email, role, teamName }
        next();
    });
};

const authorizeRoles = (...allowedRoles) => {
    return (req, res, next) => {
        if (!req.user || !allowedRoles.includes(req.user.role)) {
            return res.status(403).json({
                error: `Forbidden: Role '${req.user?.role || 'unknown'}' does not have permission.`
            });
        }
        next();
    };
};

module.exports = { authenticateToken, authorizeRoles };