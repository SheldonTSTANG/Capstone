const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'sais_super_secret_capstone_key_2026';

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'final.html'));
});

// =========================================================
// 1. AUTO-DETECT POSTGRESQL OR FALLBACK TO LOCAL JSON STORE
// =========================================================
let pool = null;
let useLocalStore = false;
const LOCAL_DB_FILE = path.join(__dirname, 'sais_data.json');

function loadLocalStore() {
    if (!fs.existsSync(LOCAL_DB_FILE)) {
        const initial = { users: [], student_athletes: [], student_classes: [], sport_schedules: [] };
        fs.writeFileSync(LOCAL_DB_FILE, JSON.stringify(initial, null, 2));
        return initial;
    }
    try {
        const parsed = JSON.parse(fs.readFileSync(LOCAL_DB_FILE, 'utf8'));
        if (!Array.isArray(parsed.users)) parsed.users = [];
        if (!Array.isArray(parsed.student_athletes)) parsed.student_athletes = [];
        if (!Array.isArray(parsed.student_classes)) parsed.student_classes = [];
        if (!Array.isArray(parsed.sport_schedules)) parsed.sport_schedules = [];
        return parsed;
    } catch {
        return { users: [], student_athletes: [], student_classes: [], sport_schedules: [] };
    }
}

function saveLocalStore(data) {
    fs.writeFileSync(LOCAL_DB_FILE, JSON.stringify(data, null, 2));
}

async function initDatabase() {
    const candidatePasswords = [
        process.env.DB_PASSWORD,
        'EsportsisSport#1',
        'postgres',
        '',
        'password',
        'admin'
    ].filter(p => p !== undefined);

    for (const pwd of candidatePasswords) {
        const cleanPwd = String(pwd).replace(/^["']|["']$/g, '');
        const testPool = new Pool({
            user: process.env.DB_USER || 'postgres',
            host: process.env.DB_HOST || 'localhost',
            database: process.env.DB_NAME || 'postgres',
            password: cleanPwd,
            port: parseInt(process.env.DB_PORT, 10) || 5432,
            connectionTimeoutMillis: 1500,
        });

        try {
            const client = await testPool.connect();
            await client.query(`
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role VARCHAR(50) NOT NULL,
                    team_name VARCHAR(100)
                );
                ALTER TABLE users ADD COLUMN IF NOT EXISTS team_name VARCHAR(100);

                CREATE TABLE IF NOT EXISTS student_athletes (
                    id SERIAL PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    first_name VARCHAR(100) NOT NULL,
                    last_name VARCHAR(100) NOT NULL,
                    team_name VARCHAR(100),
                    jersey_number INT
                );
                ALTER TABLE student_athletes ADD COLUMN IF NOT EXISTS jersey_number INT;

                CREATE TABLE IF NOT EXISTS student_classes (
                    id SERIAL PRIMARY KEY,
                    student_id TEXT NOT NULL,
                    course_code VARCHAR(50) NOT NULL,
                    course_name VARCHAR(255) NOT NULL,
                    class_start TIMESTAMPTZ,
                    class_end TIMESTAMPTZ
                );
                ALTER TABLE student_classes ADD COLUMN IF NOT EXISTS class_start TIMESTAMPTZ;
                ALTER TABLE student_classes ADD COLUMN IF NOT EXISTS class_end TIMESTAMPTZ;

                CREATE TABLE IF NOT EXISTS sport_schedules (
                    id SERIAL PRIMARY KEY,
                    coach_id TEXT,
                    team_name VARCHAR(100) NOT NULL,
                    event_title VARCHAR(255) NOT NULL,
                    class_start TIMESTAMPTZ NOT NULL,
                    class_end TIMESTAMPTZ NOT NULL
                );
            `);
            client.release();
            pool = testPool;
            useLocalStore = false;
            console.log('Connected to PostgreSQL successfully.');
            return;
        } catch (err) {
            await testPool.end().catch(() => { });
        }
    }

    useLocalStore = true;
    loadLocalStore();
    console.log('Using local sais_data.json store so registration, login, and schedules work seamlessly.');
}

// =========================================================
// 2. AUTH HELPERS & MIDDLEWARE
// =========================================================
async function hashPassword(plainPassword) {
    return await bcrypt.hash(plainPassword, 10);
}

function generateAccessToken(user) {
    return jwt.sign(
        { userId: user.id, email: user.email, role: user.role, teamName: user.team_name },
        JWT_SECRET,
        { expiresIn: '8h' }
    );
}

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Access token missing' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid or expired token' });
        req.user = user;
        next();
    });
}

// =========================================================
// 3. REGISTER ENDPOINT (COACH, ADMIN, STUDENT-ATHLETE)
// =========================================================
app.post('/register', async (req, res) => {
    const { email, password, role, firstName, lastName, teamName, jerseyNumber, classes, sportSchedules } = req.body;

    if (!email || !password || !role) {
        return res.status(400).json({ error: 'Email, password, and role are required.' });
    }

    const allowedRoles = ['coach', 'admin', 'student_athlete'];
    if (!allowedRoles.includes(role)) {
        return res.status(400).json({ error: 'Invalid system role selected.' });
    }

    const cleanEmail = email.trim().toLowerCase();
    const assignedTeam = (role === 'admin') ? null : (teamName?.trim() || 'Basketball');
    const cleanJersey = (!jerseyNumber || isNaN(parseInt(jerseyNumber, 10))) ? null : parseInt(jerseyNumber, 10);

    try {
        const passwordHash = await hashPassword(password);

        // Fallback Local Store Mode
        if (useLocalStore || !pool) {
            const store = loadLocalStore();
            if (store.users.some(u => u.email.toLowerCase() === cleanEmail)) {
                return res.status(409).json({ error: 'Email already registered.' });
            }

            const newUser = {
                id: crypto.randomUUID(),
                email: cleanEmail,
                password_hash: passwordHash,
                role,
                team_name: assignedTeam
            };
            store.users.push(newUser);

            if (role === 'student_athlete') {
                const athleteId = crypto.randomUUID();
                store.student_athletes.push({
                    id: athleteId,
                    user_id: newUser.id,
                    first_name: firstName?.trim() || 'Alex',
                    last_name: lastName?.trim() || 'Taylor',
                    team_name: assignedTeam,
                    jersey_number: cleanJersey
                });

                if (Array.isArray(classes)) {
                    for (const item of classes) {
                        if (item.courseCode && item.courseName && item.classStart && item.classEnd) {
                            store.student_classes.push({
                                id: crypto.randomUUID(),
                                student_id: athleteId,
                                course_code: item.courseCode.trim(),
                                course_name: item.courseName.trim(),
                                class_start: item.classStart,
                                class_end: item.classEnd
                            });
                        }
                    }
                }
            } else if (role === 'coach' && Array.isArray(sportSchedules)) {
                for (const item of sportSchedules) {
                    if (item.eventTitle && item.classStart && item.classEnd) {
                        store.sport_schedules.push({
                            id: crypto.randomUUID(),
                            coach_id: newUser.id,
                            team_name: assignedTeam,
                            event_title: item.eventTitle.trim(),
                            class_start: item.classStart,
                            class_end: item.classEnd
                        });
                    }
                }
            }

            saveLocalStore(store);
            const token = generateAccessToken(newUser);
            return res.status(201).json({
                message: 'User registered successfully',
                token,
                user: { id: newUser.id, email: newUser.email, role: newUser.role, teamName: newUser.team_name }
            });
        }

        // PostgreSQL Mode
        const client = await pool.connect();
        try {
            await client.query('BEGIN');

            const userResult = await client.query(
                `INSERT INTO users (email, password_hash, role, team_name)
                 VALUES ($1, $2, $3, $4)
                 RETURNING id, email, role, team_name;`,
                [cleanEmail, passwordHash, role, assignedTeam]
            );
            const newUser = userResult.rows[0];

            if (role === 'student_athlete') {
                const athleteResult = await client.query(
                    `INSERT INTO student_athletes (user_id, first_name, last_name, team_name, jersey_number)
                     VALUES ($1, $2, $3, $4, $5)
                     RETURNING id;`,
                    [String(newUser.id), firstName?.trim() || 'Alex', lastName?.trim() || 'Taylor', assignedTeam, cleanJersey]
                );
                const athleteId = athleteResult.rows[0].id;

                if (Array.isArray(classes)) {
                    for (const item of classes) {
                        if (item.courseCode && item.courseName && item.classStart && item.classEnd) {
                            await client.query(
                                `INSERT INTO student_classes (student_id, course_code, course_name, class_start, class_end)
                                 VALUES ($1, $2, $3, $4, $5);`,
                                [String(athleteId), item.courseCode.trim(), item.courseName.trim(), item.classStart, item.classEnd]
                            );
                        }
                    }
                }
            } else if (role === 'coach' && Array.isArray(sportSchedules)) {
                for (const item of sportSchedules) {
                    if (item.eventTitle && item.classStart && item.classEnd) {
                        await client.query(
                            `INSERT INTO sport_schedules (coach_id, team_name, event_title, class_start, class_end)
                             VALUES ($1, $2, $3, $4, $5);`,
                            [String(newUser.id), assignedTeam, item.eventTitle.trim(), item.classStart, item.classEnd]
                        );
                    }
                }
            }

            await client.query('COMMIT');
            const token = generateAccessToken(newUser);
            return res.status(201).json({
                message: 'User registered successfully',
                token,
                user: { id: newUser.id, email: newUser.email, role: newUser.role, teamName: newUser.team_name }
            });
        } catch (dbErr) {
            await client.query('ROLLBACK');
            throw dbErr;
        } finally {
            client.release();
        }
    } catch (err) {
        console.error('Registration Error:', err.message);
        if (err.code === '23505') {
            return res.status(409).json({ error: 'Email already registered.' });
        }
        return res.status(500).json({ error: `Registration failed: ${err.message}` });
    }
});

// =========================================================
// 4. LOGIN ENDPOINT
// =========================================================
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    const cleanEmail = email.trim().toLowerCase();

    try {
        let user = null;

        if (useLocalStore || !pool) {
            const store = loadLocalStore();
            user = store.users.find(u => u.email.toLowerCase() === cleanEmail);
        } else {
            const result = await pool.query(
                'SELECT id, email, password_hash, role, team_name FROM users WHERE LOWER(email) = $1',
                [cleanEmail]
            );
            user = result.rows[0];
        }

        if (!user || !(await bcrypt.compare(password, user.password_hash))) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const token = generateAccessToken(user);
        res.json({
            token,
            user: { id: user.id, email: user.email, role: user.role, teamName: user.team_name }
        });
    } catch (err) {
        console.error('Login error:', err.message);
        res.status(500).json({ error: 'Server error during authentication' });
    }
});

// =========================================================
// 5. PASSWORD RESET ENDPOINT
// =========================================================
app.post('/reset-password', async (req, res) => {
    const { email, newPassword } = req.body;
    if (!email || !newPassword || newPassword.length < 6) {
        return res.status(400).json({ error: 'Valid email and password (min 6 chars) required.' });
    }

    const cleanEmail = email.trim().toLowerCase();

    try {
        const newPasswordHash = await hashPassword(newPassword);

        if (useLocalStore || !pool) {
            const store = loadLocalStore();
            const user = store.users.find(u => u.email.toLowerCase() === cleanEmail);
            if (!user) return res.status(404).json({ error: 'No account found with that email address.' });
            user.password_hash = newPasswordHash;
            saveLocalStore(store);
            return res.json({ message: 'Password updated successfully. You can now log in.' });
        }

        const result = await pool.query(
            'UPDATE users SET password_hash = $1 WHERE LOWER(email) = $2 RETURNING id',
            [newPasswordHash, cleanEmail]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'No account found with that email address.' });
        }
        res.json({ message: 'Password updated successfully. You can now log in.' });
    } catch (err) {
        console.error('Password reset error:', err.message);
        res.status(500).json({ error: 'Server error while resetting password.' });
    }
});

// =========================================================
// 6. ADD SPORT SCHEDULE ENDPOINT (COACH & ADMIN)
// =========================================================
app.post('/sport-schedules', authenticateToken, async (req, res) => {
    const { userId, role, teamName: tokenTeam } = req.user;
    if (role !== 'coach' && role !== 'admin') {
        return res.status(403).json({ error: 'Only coaches and admins can add sport schedules.' });
    }

    const { teamName, events } = req.body;
    const assignedTeam = (role === 'coach' ? (tokenTeam || teamName) : teamName) || 'Basketball';

    if (!Array.isArray(events) || events.length === 0) {
        return res.status(400).json({ error: 'Please provide at least one sport schedule event.' });
    }

    try {
        if (useLocalStore || !pool) {
            const store = loadLocalStore();
            for (const item of events) {
                if (item.eventTitle && item.classStart && item.classEnd) {
                    store.sport_schedules.push({
                        id: crypto.randomUUID(),
                        coach_id: userId,
                        team_name: assignedTeam.trim(),
                        event_title: item.eventTitle.trim(),
                        class_start: item.classStart,
                        class_end: item.classEnd
                    });
                }
            }
            saveLocalStore(store);
            return res.status(201).json({ message: 'Sport schedule added successfully.' });
        }

        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            for (const item of events) {
                if (item.eventTitle && item.classStart && item.classEnd) {
                    await client.query(
                        `INSERT INTO sport_schedules (coach_id, team_name, event_title, class_start, class_end)
                         VALUES ($1, $2, $3, $4, $5);`,
                        [String(userId), assignedTeam.trim(), item.eventTitle.trim(), item.classStart, item.classEnd]
                    );
                }
            }
            await client.query('COMMIT');
            return res.status(201).json({ message: 'Sport schedule added successfully.' });
        } catch (dbErr) {
            await client.query('ROLLBACK');
            throw dbErr;
        } finally {
            client.release();
        }
    } catch (err) {
        console.error('Error adding sport schedule:', err.message);
        return res.status(500).json({ error: 'Failed to save sport schedule.' });
    }
});

// =========================================================
// 7. UNIFIED SCHEDULE RETRIEVAL (CLASSES + SPORT SCHEDULES)
// =========================================================
app.get('/all-classes', authenticateToken, async (req, res) => {
    const { userId, role, teamName } = req.user;

    try {
        // Fallback Local Store Mode
        if (useLocalStore || !pool) {
            const store = loadLocalStore();

            // Resolve student-athlete's team if needed
            let effectiveTeam = teamName;
            if (role === 'student_athlete' && !effectiveTeam) {
                const myProfile = store.student_athletes.find(sa => String(sa.user_id) === String(userId));
                if (myProfile) effectiveTeam = myProfile.team_name;
            }

            // 1. Academic Classes based on Role
            let allowedAthletes = store.student_athletes;
            if (role === 'student_athlete') {
                allowedAthletes = store.student_athletes.filter(
                    sa => String(sa.user_id) === String(userId)
                );
            } else if (role === 'coach' && effectiveTeam) {
                allowedAthletes = store.student_athletes.filter(
                    sa => (sa.team_name || '').toLowerCase().trim() === effectiveTeam.toLowerCase().trim()
                );
            }
            // Note: role === 'admin' keeps ALL student_athletes

            const allowedAthleteIds = new Set(allowedAthletes.map(sa => String(sa.id)));

            const classRecords = store.student_classes
                .filter(sc => allowedAthleteIds.has(String(sc.student_id)))
                .map(sc => {
                    const athlete = allowedAthletes.find(sa => String(sa.id) === String(sc.student_id)) || {};
                    return {
                        id: sc.id,
                        student_id: sc.student_id,
                        user_id: athlete.user_id,
                        course_code: sc.course_code,
                        course_name: sc.course_name,
                        class_start: sc.class_start,
                        class_end: sc.class_end,
                        first_name: athlete.first_name || 'Alex',
                        last_name: athlete.last_name || 'Taylor',
                        team_name: athlete.team_name || 'Basketball',
                        event_type: 'class'
                    };
                });

            // 2. Sport Schedules based on Role
            let sportRecords = store.sport_schedules || [];
            if ((role === 'coach' || role === 'student_athlete') && effectiveTeam) {
                sportRecords = sportRecords.filter(
                    sp => (sp.team_name || '').toLowerCase().trim() === effectiveTeam.toLowerCase().trim()
                );
            }
            // Note: role === 'admin' keeps ALL sport_schedules

            const formattedSports = sportRecords.map(sp => ({
                id: sp.id,
                student_id: null,
                user_id: sp.coach_id,
                course_code: 'SPORT',
                course_name: sp.event_title,
                class_start: sp.class_start,
                class_end: sp.class_end,
                first_name: 'Team',
                last_name: 'Schedule',
                team_name: sp.team_name || 'Basketball',
                event_type: 'sport'
            }));

            return res.json([...classRecords, ...formattedSports]);
        }

        // PostgreSQL Mode
        let effectiveTeam = teamName;
        if (role === 'student_athlete' && !effectiveTeam) {
            const saRes = await pool.query(
                'SELECT team_name FROM student_athletes WHERE CAST(user_id AS TEXT) = CAST($1 AS TEXT) LIMIT 1',
                [String(userId)]
            );
            if (saRes.rows[0]) effectiveTeam = saRes.rows[0].team_name;
        }

        // 1. Query Academic Classes
        let classQuery = `
            SELECT 
                sc.id, 
                sc.student_id,
                sa.user_id,
                sc.course_code,
                sc.course_name, 
                sc.class_start, 
                sc.class_end,
                sa.first_name, 
                sa.last_name, 
                sa.team_name,
                'class' AS event_type
            FROM student_athletes sa
            JOIN student_classes sc ON CAST(sc.student_id AS TEXT) = CAST(sa.id AS TEXT)
            WHERE sc.class_start IS NOT NULL AND sc.class_end IS NOT NULL
        `;
        const classParams = [];

        if (role === 'student_athlete') {
            classQuery += ` AND CAST(sa.user_id AS TEXT) = CAST($1 AS TEXT)`;
            classParams.push(String(userId));
        } else if (role === 'coach' && effectiveTeam) {
            classQuery += ` AND LOWER(TRIM(sa.team_name)) = LOWER(TRIM($1))`;
            classParams.push(effectiveTeam);
        }

        classQuery += ` ORDER BY sc.class_start ASC;`;
        const classResult = await pool.query(classQuery, classParams);

        // 2. Query Sport Schedules
        let sportQuery = `
            SELECT
                sp.id,
                NULL AS student_id,
                sp.coach_id AS user_id,
                'SPORT' AS course_code,
                sp.event_title AS course_name,
                sp.class_start,
                sp.class_end,
                'Team' AS first_name,
                'Schedule' AS last_name,
                sp.team_name,
                'sport' AS event_type
            FROM sport_schedules sp
            WHERE sp.class_start IS NOT NULL AND sp.class_end IS NOT NULL
        `;
        const sportParams = [];

        if ((role === 'coach' || role === 'student_athlete') && effectiveTeam) {
            sportQuery += ` AND LOWER(TRIM(sp.team_name)) = LOWER(TRIM($1))`;
            sportParams.push(effectiveTeam);
        }

        sportQuery += ` ORDER BY sp.class_start ASC;`;
        const sportResult = await pool.query(sportQuery, sportParams);

        res.json([...classResult.rows, ...sportResult.rows]);
    } catch (err) {
        console.error('Error fetching schedules:', err.message);
        res.status(500).json({ error: 'Failed to retrieve schedules' });
    }
});

initDatabase().then(() => {
    app.listen(PORT, () => {
        console.log(`SAIS Backend Server running on http://localhost:${PORT}`);
    });
});