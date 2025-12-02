import pool from '../database/db.js';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

export const register = async (req, res) => {
  const { email, username, password } = req.body;

  if (!email || !username || !password) {
    return res.status(400).json({ error: 'Missing fields' });
  }

  try {
    // Check if email exists
    const emailCheck = await pool.query(
      'SELECT id FROM users WHERE email = $1',
      [email]
    );
    if (emailCheck.rows.length > 0) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    // Check if username exists
    const usernameCheck = await pool.query(
      'SELECT id FROM users WHERE username = $1',
      [username]
    );
    if (usernameCheck.rows.length > 0) {
      return res.status(400).json({ error: 'Username not available' });
    }

    // Hash password
    const hashed = await bcrypt.hash(password, 10);

    // Create user
    const created = await pool.query(
      `INSERT INTO users (email, username, password)
       VALUES ($1, $2, $3)
       RETURNING id, email, username`,
      [email, username, hashed]
    );

    const user = created.rows[0];

    const payload = { id: user.id, email: user.email, username: user.username };

    const accessToken = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });
    const refreshToken = jwt.sign(payload, process.env.JWT_REFRESH_SECRET, { expiresIn: '30d' });

    res.cookie('accessToken', accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'none'
    });

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'none'
    });

    return res.json({ user: payload });

  } catch (err) {
    console.log(err);
    return res.status(500).json({ error: 'Server error' });
  }
};


export const login = async (req, res) => {
  const { identifier, password } = req.body;

  if (!identifier || !password) {
    return res.status(400).json({ error: 'Missing fields' });
  }

  try {
    // identifier can be either email OR username
    const found = await pool.query(
      `SELECT * FROM users 
       WHERE email = $1 OR username = $1`,
      [identifier]
    );

    if (found.rows.length === 0) {
      return res.status(400).json({ error: 'User not found' });
    }

    const user = found.rows[0];

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) return res.status(400).json({ error: 'Incorrect password' });

    const payload = {
      id: user.id,
      email: user.email,
      username: user.username
    };

    const accessToken = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });
    const refreshToken = jwt.sign(payload, process.env.JWT_REFRESH_SECRET, { expiresIn: '30d' });

    res.cookie('accessToken', accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'none'
    });

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'none'
    });

    return res.json({ user: payload });

  } catch (err) {
    console.log(err);
    return res.status(500).json({ error: 'Server error' });
  }
};

export const refreshToken = (req, res) => { const token = req.cookies.refreshToken; if (!token) return res.status(401).json({ error: 'No refresh token' }); jwt.verify(token, process.env.JWT_REFRESH_SECRET, (err, user) => { if (err) return res.status(403).json({ error: 'Invalid refresh token' }); const newAccessToken = jwt.sign( { id: user.id, address: user.address }, process.env.JWT_SECRET, { expiresIn: '1h' } ); res.cookie('accessToken', newAccessToken, { httpOnly: true, secure: true, sameSite: 'none' }); return res.json({ message: 'Refreshed' }); }); };