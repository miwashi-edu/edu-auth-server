# edu-auth-server

## Instructions

```bash
npm install helmet
```

### ./src/server.js

```bash
cat > ./src/server.js << 'EOF'
const express = require('express');
const cors = require('cors');
const dataRoutes = require('./routes/data_routes');
const helmet = require('helmet');  // Import Helmet
const { createLogger, format, transports } = require('winston');

const app = express();

// Initialize Helmet before other middleware
app.use(helmet());

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

## Content Security Policy CSP

> Imagine your website as a club with a VIP list. Content Security Policy acts like a bouncer who only allows scripts, images, and other resources from "known" places that you specify to load and run on your site. This helps in preventing unauthorized or harmful code from sneaking in.
> 
```js
const csp = require('helmet-csp');

app.use(csp({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'unsafe-inline'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", "img.com"],
  }
}));
```

## HTTP Strict Transport Security (HSTS) settings

> Think of HSTS like a VIP pass that tells your browser, "Always use a secure, encrypted connection (HTTPS) when visiting this website, don't settle for less." This makes it much harder for attackers to eavesdrop or tamper with data sent to and from the website.
> 
```js
const hsts = require('hsts');

app.use(hsts({
  maxAge: 31536000,
  includeSubDomains: true,
  preload: true
}));
```

## Example

```js
app.use(helmet());
app.use(csp({ /* your policy here */ }));
app.use(hsts({ /* your options here */ }));
// ...other configurations
```




