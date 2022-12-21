const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();

require('dotenv').config();

// middleware
app.use(express.json());

let refreshToken = [];

// routes
// registration

// login
app.post('/login', (req, res, next) => {
    const username = req.body.username;
    const password = req.body.password;

    if (username === 'jisoo' && password === '1234') {
        const access_token = jwt.sign(
            { sub: username },
            process.env.JWT_ACCESS_SECRET,
            { expiresIn: process.env.JWT_ACCESS_TIME }
        );

        const refresh_token = GenerateRefreshToken(username);

        return res.json({
            status: true,
            message: 'login success',
            data: { access_token, refresh_token },
        });
    }

    res.status(401).json({ status: true, message: 'login fail' });
});

app.post('/token', verifyRefreshToken, (req, res, next) => {
    const username = req.userData.sub;
    const access_token = jwt.sign(
        { sub: username },
        process.env.JWT_ACCESS_SECRET,
        { expiresIn: process.env.JWT_ACCESS_TIME }
    );
    const refresh_token = GenerateRefreshToken(username);

    return res.json({
        status: true,
        message: 'success',
        data: { access_token, refresh_token },
    });
});

// dashboard
app.get('/dashboard', verifyToken, (req, res, next) => {
    return res
        .status(200)
        .json({ status: true, message: 'Hello from dashboard' });
});

// logout
app.get('/logout', verifyToken, (req, res, next) => {
    const username = req.useData.sub;

    // remove the refresh token
    refreshToken = refreshToken.filter((x) => x.username !== username);
    return res.status(200).json({ status: true, message: 'success logout' });
});

// Custom middleware
function verifyToken(req, res, next) {
    try {
        // Bearer tokenstring
        const token = req.headers.authorization.split(' ')[1];

        const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
        req.useData = decoded;
        next();
    } catch (error) {
        return res.status(401).json({
            status: false,
            message: 'your session is not valid',
            data: error,
        });
    }
}

function verifyRefreshToken(req, res, next) {
    const token = req.body.token;

    if (token === null) {
        return res.status(401).json({
            status: false,
            message: 'your session is not valid',
            data: error,
        });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET);
        req.userData = decoded;

        console.log(refreshToken);

        // verify if token is in store or not
        const storedRefreshToken = refreshToken.find(
            (x) => x.username === decoded.sub
        );

        if (storedRefreshToken === undefined) {
            return res.status(401).json({
                status: false,
                message: 'Invalid request. Token is not in stored',
            });
        }

        if (storedRefreshToken.token != token) {
            return res.status(401).json({
                status: false,
                message: 'Invalid request. Token is not same in stored',
            });
        }
        next();
    } catch (error) {
        return res.status(401).json({
            status: false,
            message: 'your session is not valid',
            data: error,
        });
    }
}

function GenerateRefreshToken(username) {
    const refresh_token = jwt.sign(
        { sub: username },
        process.env.JWT_REFRESH_SECRET,
        { expiresIn: process.env.JWT_REFRESH_TIME }
    );

    const storedRefreshToken = refreshToken.find(
        (x) => x.username === username
    );

    if (storedRefreshToken === undefined) {
        refreshToken.push({
            username,
            token: refresh_token,
        });
    } else {
        refreshToken[
            refreshToken.findIndex((x) => x.username === username)
        ].token = refresh_token;
    }

    return refresh_token;
}

app.listen(3000, () => {
    console.log('server is running...');
});
