# edu-auth-server

## Instructions

```bash
npm install react-helmet
```

## Backend Server

### ./src/server.js

```bash
cat > ./src/App.js << 'EOF'
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
app.use('/health', require('express-healthcheck-improved')());

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

## Health Check Services

Services That Monitor Health Checks
===================================

*   **AWS CloudWatch**
    *   Path: Configurable (e.g., `/health`)
    *   Expected JSON: Usually just expects an HTTP 200 response.
*   **Google Cloud Monitoring**
    *   Path: Configurable (e.g., `/health`)
    *   Expected JSON: May expect fields like `status` to be "UP".
*   **New Relic**
    *   Path: `/health`
    *   Expected JSON: Customizable; often a 200 OK is sufficient.
*   **Datadog**
    *   Path: Customizable (e.g., `/health`)
    *   Expected JSON: Can be configured to check for specific fields.
*   **Pingdom**
    *   Path: `/health`
    *   Expected JSON: Usually just expects a 200 OK HTTP status.
*   **Prometheus**
    *   Path: Often `/metrics`, but can also include `/health`
    *   Expected JSON: Can be set to expect certain metrics or statuses.
*   **Uptime Robot**
    *   Path: `/health`
    *   Expected JSON: Typically expects HTTP 200.
*   **Sensu**
    *   Path: Configurable (e.g., `/health`)
    *   Expected JSON: May include custom fields like `status`, `uptime`, etc.
*   **Site24x7**
    *   Path: `/health`
    *   Expected JSON: Usually just expects HTTP 200 OK.
*   **PagerDuty**
    *   Path: Customizable
    *   Expected JSON: Can be configured to expect specific JSON fields.
