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
touch ./src/service.js ./src/server.js ./src/routes/auth_routes.js ./src/passport_config.js ./src/auth/users.js .env
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
const { PORT } = require('../config');
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

module.exports = router;
EOF
```

## ./src/controllers/auth_controllers.js

```bash
cat > ./src/controllers/auth_controller.js << 'EOF'
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
        const token = jwt.sign({ userId: user.id, role: user.role }, 'YourJWTSecretKey', { expiresIn: '1h' });
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

    const newToken = jwt.sign({ userId: user.id, role: user.role }, 'YourJWTSecretKey', { expiresIn: '1h' });
    res.json({ token: newToken });
};
EOF
```
