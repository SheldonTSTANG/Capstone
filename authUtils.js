const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const SALT_ROUNDS = 10;
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_jwt_key_2026';

const hashPassword = async (plaintext) => {
    return await bcrypt.hash(plaintext, SALT_ROUNDS);
};

const verifyPassword = async (plaintext, hash) => {
    return await bcrypt.compare(plaintext, hash);
};

const generateAccessToken = (user) => {
    return jwt.sign(
        {
            userId: user.id,
            email: user.email,
            role: user.role,
            teamName: user.team_name || null
        },
        JWT_SECRET,
        { expiresIn: '8h' }
    );
};

module.exports = { hashPassword, verifyPassword, generateAccessToken };