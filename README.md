# edu-auth-server

> Vi lägger till access loggar
> 
## Instructions

```bash
npm install morgan rotating-file-stream
npm install @elastic/ecs-morgan-format
```

## ./src/server.js

```bash
cat > ./src/server.js << 'EOF'
const express = require('express');
const cors = require('cors');
const passport = require('passport');
const morgan = require('morgan');
const ecsFormat = require('@elastic/ecs-morgan-format')
const fs = require('fs');
const path = require('path');
const rfs = require('rotating-file-stream');
const authRoutes = require('./routes/auth_routes');
require('./auth/passport_config.js');  // Importing the Passport setup

const app = express();

// Create a logs directory, if it doesn't exist
const logDirectory = path.join(__dirname, '../logs');
fs.existsSync(logDirectory) || fs.mkdirSync(logDirectory);

// Create a rotating write stream
const accessLogStream = fs.createWriteStream(path.join(__dirname, '../logs/access.log'), {
  interval: '1d', // rotate daily
  path: logDirectory
});

// Setup morgan logging format and output
const morganFormat = ':remote-addr - :remote-user [:date[clf]] ":method :url HTTP/:http-version" :status :res[content-length] ":referrer" ":user-agent"';
//app.use(morgan(ecsFormat(), { stream: accessLogStream }))

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(passport.initialize());

// Routes
app.use('/auth', authRoutes);

module.exports = app;
EOF
```

