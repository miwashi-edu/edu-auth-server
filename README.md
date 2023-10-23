# edu-auth-server

## Instructions

```bash
npm install winston
```

# Backend

## ./src/server.js

```bash
cat > ./src/server.js << 'EOF'
const express = require('express');
const cors = require('cors');
const dataRoutes = require('./routes/data_routes');
const { createLogger, format, transports } = require('winston');

const app = express();

// Setup logger
const logger = createLogger({
    format: format.combine(
        format.timestamp(),
        format.json()
    ),
    transports: [
        new transports.File({ filename: './log/audit.log' })
    ]
});

app.use(cors());
app.use(express.json());

// Audit Logging Middleware for Incoming Requests
app.use((req, res, next) => {
    if (req.user) {
        logger.info('Request Received', {
            method: req.method,
            url: req.originalUrl,
            userId: req.user.id,
            role: req.user.role
        });
    }
    next();
});

// JWT Token Verification Middleware
app.use(async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(403).send('Access Denied');
    try {
        const response = await fetch('http://localhost:3001/auth/verify-token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ token })
        });

        const data = await response.json();
        if (!response.ok) throw new Error(data.message);
        req.user = data.user;
        next();
    } catch (error) {
        logger.error('JWT Token Verification Error', { message: error.message });
        res.status(401).send('Invalid Token');
    }
});

app.use('/data', dataRoutes);

// Error Handling and Logging
app.use((err, req, res, next) => {
    logger.error('Error Encountered', {
        message: err.message,
        stack: err.stack,
        userId: req.user ? req.user.id : 'unknown'
    });
    res.status(500).send('Internal Server Error');
});

module.exports = app;
EOF
```

## ./src/logger.js

```bash
cat > ./src/logger.js << 'EOF'
const { createLogger, format, transports } = require('winston');

const logger = createLogger({
    format: format.combine(
        format.timestamp(),
        format.json()
    ),
    transports: [
        new transports.File({ filename: './logs/audit.log' })
    ]
});
module.exports = logger;
EOF
```

## ./src/routes/data_routes.js

```bash
cat > ./src/routes/data_routes.js << 'EOF'
const express = require('express');
const router = express.Router();
const logger = require('../logger');

router.get('/', (req, res) => {
    if (req.user.role === 'admin') {
        logger.info('Admin Data Accessed', { userId: req.user.id });
        return res.json({ data: 'Secret data for admin!' });
    } else {
        logger.info('User Data Accessed', { userId: req.user.id });
        return res.json({ data: 'Secret data for user!' });
    }
});

router.get('/users', (req, res) => {
    if (req.user.role !== 'admin') {
        logger.warn('Unauthorized Access Attempt to Users Data', { userId: req.user.id });
        return res.status(403).send('Access Denied');
    }
    logger.info('All Users Data Accessed', { userId: req.user.id });
    res.json({ data: 'List of all users!' });
});

router.get('/user', (req, res) => {
    logger.info('User Data Retrieved', { userId: req.user.id });
    res.json({ data: `Data for user with ID: ${req.user.id}` });
});

module.exports = router;
EOF
```


## Överkurs

[ELK](https://www.elastic.co/blog/elasticsearch-free-open-limitless)

```bash
npm install winston-elasticsearch
```

```js
const { createLogger, format } = require('winston');
const { ElasticsearchTransport } = require('winston-elasticsearch');

const logger = createLogger({
    format: format.combine(
        format.timestamp(),
        format.json()
    ),
    transports: [
        new ElasticsearchTransport({
            level: 'info',
            clientOpts: { node: 'http://localhost:9200' }
        })
    ]
});
``
