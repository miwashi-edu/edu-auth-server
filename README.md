# edu-auth-server

## Structure

```
/src
    /auth
        users.js
        passport_config.js
    /routes
        auth_routes.js
    /controller
        auth_controller.js
    service.js
    server.js
```

## Instructions

```bash
mkdir auth-server && cd auth-server
npm install passport passport-local

npm init -y
npm install dotenv express express-validator cors bcrypt jsonwebtoken dotenv
npm install -D nodemon jest

npm pkg set main="./src/service.js"
npm pkg set scripts.start="node ./src/service.js"
npm pkg set scripts.dev="nodemon ./src/service.js"
npm pkg set scripts.test="jest"

# Create files
mkdir -p ./src/{routes,controllers,auth}
touch ./src/service.js ./src/server.js ./src/routes/auth_routes.js ./src/passport_.js ./src/auth/users.js .env
```

### .env

```bash
cat > .env << 'EOF'
# Generate a key with
# node -e "console.log(require('crypto').randomBytes(256).toString('base64'));"
JWT_SECRET_KEY=YourJWTSecretKey
EOF
```

### ./src/service.js

```bash
cat > ./src/service.js << 'EOF'
const { PORT } = require('./');
const app = require('./server.js');

app.listen(PORT, () => {
    console.log(`http server listening on port ${PORT}`)
});
EOF
```

### ./src/config.js

```bash
cat > ./src/config.js << 'EOF'
require('dotenv').config();
const PORT = process.env.PORT || 3001
const JWT_SECRET_KEY = process.env.JWT_SECRET_KEY || "YourJWTSecretKey"

module.exports = {
    PORT,
    JWT_SECRET_KEY
};
EOF
```

### ./src/server.js

```bash
cat > ./src/server.js << 'EOF'
const express = require('express');
const cors = require('cors');
const passport = require('passport');
const authRoutes = require('./routes/auth_routes');
require('./auth/passport_config.js');  // Importing the Passport setup

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({extended: true}));
app.use(passport.initialize());

// Routes
app.use('/auth', authRoutes);

module.exports = app;
EOF
```

### ./src/auth/users.js

```bash
cat > ./src/auth/users.js << 'EOF'
const bcrypt = require("bcrypt");
const users = [
    { id: 1, email: 'user@example.com', password: bcrypt.hashSync('password', 10), role: 'user' }
];  // Example user store

module.exports = users;
EOF
```

### ./src/auth/passport_config.js

```bash
cat > ./src/auth/passport_config.js << 'EOF'
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const users = require('./users');

passport.use(new LocalStrategy({
        usernameField: 'email',
        passwordField: 'password'
    },
    async (email, password, done) => {
        const user = users.find(u => u.email === email);
        if (user == null) {
            return done(null, false, { message: 'No user with that email' });
        }

        try {
            if (await bcrypt.compare(password, user.password)) {
                return done(null, user);
            } else {
                return done(null, false, { message: 'Password incorrect' });
            }
        } catch (e) {
            return done(e);
        }
    }
));

module.exports = passport;
EOF
```

### ./src/routes/auth_routes.js

> Validation affects flow control, and it would be more intuetively to have it in controller, but in this case code readibilty trumps separation of concern.
> Also having all validators in the routes helps with validation reuse.

```bash
cat > ./src/routes/auth_routes.js << 'EOF'
const express = require('express');
const { check } = require('express-validator');
const authController = require('../controllers/auth_controller');

const router = express.Router();

router.post('/login',
    [
        check('email').isEmail().withMessage('Enter a valid email address'),
        check('password').notEmpty().withMessage('Password cannot be empty')
    ],
    authController.login
);

router.post('/register',
    [
        check('email').isEmail().withMessage('Enter a valid email address'),
        check('password').isLength({ min: 5 }).withMessage('Password must be at least 5 characters')
    ],
    authController.register
);

router.get('/users', authController.get_all_users);

router.get('/current-user', authController.current_user);

router.post('/renew-token', authController.renew_token);

router.post('/verify-token', authController.verify_token);

module.exports = router;
EOF
```

## ./src/controllers/auth_controllers.js

```bash
cat > ./src/controllers/auth_controller.js << 'EOF'
const {JWT_SECRET_KEY} = require('../config');
const passport = require('passport');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { validationResult } = require('express-validator');
const users = require('../auth/users');

exports.login = (req, res, next) => {
    passport.authenticate('local', { session: false }, (err, user, info) => {
        if (err || !user) {
            return res.status(400).json({
                message: 'Something is not right',
                user: user
            });
        }
        const token = jwt.sign({ userId: user.id, role: user.role }, JWT_SECRET_KEY, { expiresIn: '1h' });
        return res.json({ token });
    })(req, res, next);
};

exports.register = (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { email, password } = req.body;
    if (users.find(u => u.email === email)) return res.status(400).json({ message: 'User already exists' });

    const hashedPassword = bcrypt.hashSync(password, 10);
    const newUser = { id: users.length + 1, email, password: hashedPassword, role: 'user' };
    users.push(newUser);

    res.status(201).json({ message: 'User registered successfully' });
};

exports.get_all_users = (req, res) => {
    const userList = users.map(user => {
        return { id: user.id, email: user.email };
    });
    res.json(userList);
};

exports.current_user = (req, res) => {
    const user = users.find(u => u.id === req.user.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const { password, ...restOfUser } = user;
    res.json(restOfUser);
};

exports.renew_token = (req, res) => {
    const user = users.find(u => u.id === req.user.userId);
    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }

    const newToken = jwt.sign({ userId: user.id, role: user.role }, JWT_SECRET_KEY, { expiresIn: '1h' });
    res.json({ token: newToken });
};

exports.verify_token = (req, res) => {
    const token = req.body.token;

    if (!token) return res.status(400).send({ message: 'Token is required' });

    try {
        const decoded = jwt.verify(token, JWT_SECRET_KEY);
        res.json({ user: decoded });
    } catch (error) {
        res.status(401).send({ message: 'Invalid Token' });
    }
};
EOF
```

# Frontend 

> Endast små ändrignar.

## App.js

```bash
cat > ./src/App.js << 'EOF'
import React, { useState } from 'react';
import './App.css';

function App() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [data, setData] = useState(null);
  const [isAuthenticated, setAuthenticated] = useState(false);

  const handleLogin = async () => {
    try {
      const response = await fetch('http://localhost:3001/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });

      const result = await response.json();

      if (!response.ok) {
        throw new Error(result.message || 'Login failed');
      }

      localStorage.setItem('access_token', result.token);
      setAuthenticated(true);
    } catch (error) {
      alert(error.message);
    }
  };

  const handleRegister = async () => {
    try {
      const response = await fetch('http://localhost:3001/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });

      const result = await response.json();

      if (!response.ok) {
        throw new Error(result.message || 'Registration failed');
      }

      alert('Registration successful! You can now login.');
    } catch (error) {
      alert(error.message);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('access_token');
    setAuthenticated(false);
    setData(null);
  };

  const fetchData = async () => {
    try {
      const token = localStorage.getItem('access_token');
      const response = await fetch('http://localhost:3002/data/users', {
        headers: {
          Authorization: `Bearer ${token}`
        }
      });

      const result = await response.json();

      if (!response.ok) {
        throw new Error(result.message || 'Failed to fetch data from backend');
      }

      setData(result);
    } catch (error) {
      if (error.message === 'Unauthorized') {
        handleLogout();
        alert('Session expired. Please login again.');
      } else {
        alert(error.message);
      }
    }
  };

  return (
      <div className="App">
        <header className="App-header">
          {isAuthenticated ? (
              <>
                {data ? <p>{JSON.stringify(data)}</p> : <button onClick={fetchData}>Fetch Data</button>}
                <button onClick={handleLogout}>Logout</button>
              </>
          ) : (
              <div className="auth-container">
                <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="Email" className="input-field" />
                <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Password" className="input-field" />
                <button onClick={handleLogin} className="auth-button">Login</button>
                <button onClick={handleRegister} className="auth-button">Register</button>
              </div>
          )}
        </header>
      </div>
  );
}

export default App;
EOF
```


# Backend

## ./src/server.js

> Vi ändrar bara i hur säkerheten hanteras, nu görs all token verifiering i auth servern och lösenord behöver inte sparas i alla servrar.


```bash
cat > ./src/server.js << 'EOF'
const express = require('express');
const cors = require('cors');
const dataRoutes = require('./routes/data_routes');

const app = express();
app.use(cors());
app.use(express.json());

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
        console.log(error);
        res.status(401).send('Invalid Token');
    }
});

app.use('/data', dataRoutes);

module.exports = app;

EOF
```

## ./src/routes/data_routes.js

```bash
cat > ./src/server.js << 'EOF'
const express = require('express');

const router = express.Router();

router.get('/', (req, res) => {
  if (req.user.role === 'admin') {
    return res.json({ data: 'Secret data for admin!' });
  } else {
    return res.json({ data: 'Secret data for user!' });
  }
});

router.get('/users', (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).send('Access Denied');
  }
  res.json({ data: 'List of all users!' });
});

router.get('/user', (req, res) => {
  res.json({ data: `Data for user with ID: ${req.user.id}` });
});

module.exports = router;
EOF
```
