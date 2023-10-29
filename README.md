# edu-auth-server - frontend

## Structure

## Instructions

```bash
npm install passport passport-local
```

### ./src/App.js

```bash
cat > ./src/App.js << 'EOF'
import React, { useState, useEffect } from 'react';
import CookieConsent from 'react-cookie-consent';
import './App.css';

function App() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [data, setData] = useState(null);
  const [isAuthenticated, setAuthenticated] = useState(false);
  const [consentGiven, setConsentGiven] = useState(false);

  useEffect(() => {
    // Check if the user has given consent
    const consentStatus = localStorage.getItem('cookie_consent');
    if (consentStatus === 'true') {
      setConsentGiven(true);
    }
  }, []);

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

  const handleLogout = () => {
    localStorage.removeItem('access_token');
    setAuthenticated(false);
    setData(null);
  };


  const handleLogin = async () => {
    // Check if consent is given before allowing login
    if (!consentGiven) {
      alert('Please give consent to cookies before logging in.');
      return;
    }

    try {
      const response = await fetch('http://localhost:3001/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
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
    // Check if consent is given before allowing registration
    if (!consentGiven) {
      alert('Please give consent to cookies before registering.');
      return;
    }

    try {
      const response = await fetch('http://localhost:3001/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
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

  // Rest of your code remains unchanged

  return (
      <div className="App">
        <CookieConsent
            location="bottom"
            buttonText={
              <>
                I Consent
                <a href="/gdpr-info" style={{ marginLeft: '5px', textDecoration: 'underline' }}>
                  Learn More
                </a>
              </>
            }
            cookieName="gdpr-consent"
            style={{ background: '#2B373B' }}
            buttonStyle={{ color: '#4e503b', fontSize: '13px' }}
            expires={150}
            enableDeclineButton
            onAccept={() => {
              localStorage.setItem('cookie_consent', 'true');
              setConsentGiven(true);
            }}
            onDecline={() => {
              localStorage.setItem('cookie_consent', 'false');
              setConsentGiven(false);
            }}
        >
          This website uses cookies to enhance the user experience.{' '}
          <span style={{ fontSize: '6px' }}>By consenting your revoke all right to your first born!</span>
        </CookieConsent>

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
                <button onClick={handleLogin} className="auth-button" disabled={!consentGiven}>
                  Login
                </button>
                <button onClick={handleRegister} className="auth-button" disabled={!consentGiven}>
                  Register
                </button>
              </div>
          )}
        </header>
      </div>
  );
}

export default App;
EOF
```
