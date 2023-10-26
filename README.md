# edu-auth-server

## Instructions

```bash
npm install react-helmet
```

### ./src/App.js

```bash
cat > ./src/App.js << 'EOF'
import React, { useState } from 'react';
import { Helmet } from 'react-helmet';  // Import react-helmet
import './App.css';

function App() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [data, setData] = useState(null);
  const [isAuthenticated, setAuthenticated] = useState(false);

  const handleLogin = async () => {
    // ... (your existing code)
  };

  const handleRegister = async () => {
    // ... (your existing code)
  };

  const handleLogout = () => {
    // ... (your existing code)
  };

  const fetchData = async () => {
    // ... (your existing code)
  };

  return (
    <div className="App">
      <Helmet>
        <title>My Secure App</title>
        <meta name="description" content="This is my secure React app" />
      </Helmet>
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
import React, { useState } from 'react';
import { Helmet } from 'react-helmet';
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
      <Helmet>
        <title>My Secure App</title>
        <meta name="description" content="This is my secure React app" />
      </Helmet>
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

## SEO

```js
<Helmet>
  {/* Basic SEO */}
  <title>My Secure App</title>
  <meta name="description" content="This is my secure React app" />
  <meta name="keywords" content="secure, react, app" />
  
  {/* OpenGraph Protocol for Facebook, LinkedIn */}
  <meta property="og:title" content="My Secure App" />
  <meta property="og:description" content="This is my secure React app" />
  <meta property="og:image" content="path/to/your/image.jpg" />
  <meta property="og:url" content="http://www.example.com" />
  
  {/* Twitter Cards */}
  <meta name="twitter:title" content="My Secure App" />
  <meta name="twitter:description" content="This is my secure React app" />
  <meta name="twitter:image" content="path/to/your/image.jpg" />
  <meta name="twitter:card" content="summary_large_image" />

  {/* Google Search Console Verification */}
  <meta name="google-site-verification" content="your-google-verification-code" />
  
  {/* Google Analytics (replace 'UA-XXXXXXXXX-Y' with your tracking ID) */}
  <script>
    {
      `
      window.dataLayer = window.dataLayer || [];
      function gtag(){dataLayer.push(arguments);}
      gtag('js', new Date());
      gtag('config', 'UA-XXXXXXXXX-Y');
      `
    }
  </script>
</Helmet>
```

