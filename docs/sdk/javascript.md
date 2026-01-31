# JavaScript/TypeScript SDK

The official TypeScript SDK for Kayan IAM.

## Installation

```bash
npm install kayan.js
# or
yarn add kayan.js
```

---

## Quick Start

### Simple Client (Recommended)

```typescript
import { KayanClient } from 'kayan.js';

const client = new KayanClient({
  baseURL: 'http://localhost:8080/api/v1',
});

// Register
await client.register({ email: 'user@example.com' }, 'password123');

// Login
const { token } = await client.login('user@example.com', 'password123');

// Get current user
const user = await client.whoami(token);
```

---

## Full API Access

For complete control, use the generated SDK:

```typescript
import { 
  register, 
  login, 
  whoami,
  webauthnLoginBegin,
  adminListUsers,
} from 'kayan.js';

import { client } from 'kayan.js/generated';

// Configure base URL
client.setConfig({ baseUrl: 'http://localhost:8080' });

// Registration
const { data: user } = await register({
  body: { 
    traits: { email: 'user@example.com' }, 
    password: 'secret123' 
  }
});

// Login
const { data: session } = await login({
  body: { 
    identifier: 'user@example.com', 
    password: 'secret123' 
  }
});

// Authenticated requests
const { data: me } = await whoami({
  headers: { Authorization: `Bearer ${session.token}` }
});
```

---

## Simple Client Methods

| Method | Description |
|--------|-------------|
| `register(traits, password)` | Create new user |
| `login(identifier, password)` | Authenticate |
| `loginMFA(identifier, code)` | Complete MFA |
| `logout(token)` | End session |
| `whoami(token)` | Get current user |
| `recoveryInitiate(email)` | Start password reset |
| `recoveryReset(token, password)` | Complete reset |

---

## WebAuthn (Passkeys)

```typescript
import { 
  webauthnRegisterBegin, 
  webauthnRegisterFinish,
  webauthnLoginBegin,
  webauthnLoginFinish 
} from 'kayan.js';

// Registration
const { data: options } = await webauthnRegisterBegin({
  headers: { Authorization: `Bearer ${token}` },
  body: { user_name: 'My Passkey' }
});

// Use browser's WebAuthn API
const credential = await navigator.credentials.create({
  publicKey: options
});

await webauthnRegisterFinish({
  headers: { Authorization: `Bearer ${token}` },
  body: credential
});

// Login
const { data: loginOptions } = await webauthnLoginBegin({
  body: { identifier: 'user@example.com' }
});

const assertion = await navigator.credentials.get({
  publicKey: loginOptions
});

const { data: session } = await webauthnLoginFinish({
  body: assertion
});
```

---

## Admin Operations

```typescript
import { 
  adminListUsers, 
  adminCreateUser, 
  adminDeleteUser 
} from 'kayan.js';

// List users
const { data: users } = await adminListUsers({
  headers: { Authorization: `Bearer ${adminToken}` },
  query: { limit: 10, offset: 0 }
});

// Create user
const { data: newUser } = await adminCreateUser({
  headers: { Authorization: `Bearer ${adminToken}` },
  body: {
    traits: { email: 'newuser@example.com' },
    password: 'tempPassword123'
  }
});

// Delete user
await adminDeleteUser({
  headers: { Authorization: `Bearer ${adminToken}` },
  path: { id: 'user_123' }
});
```

---

## React Example

```tsx
import { useState } from 'react';
import { KayanClient } from 'kayan.js';

const client = new KayanClient({
  baseURL: '/api/v1',
});

function LoginForm() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const { token } = await client.login(email, password);
      localStorage.setItem('token', token);
      window.location.href = '/dashboard';
    } catch (err) {
      setError('Invalid credentials');
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <input 
        type="email" 
        value={email} 
        onChange={e => setEmail(e.target.value)} 
      />
      <input 
        type="password" 
        value={password} 
        onChange={e => setPassword(e.target.value)} 
      />
      <button type="submit">Login</button>
      {error && <p>{error}</p>}
    </form>
  );
}
```

---

## Regenerating the SDK

If the OpenAPI spec changes:

```bash
cd kayan-js
npm run generate
```

---

## Types

All types are auto-generated:

```typescript
import type { 
  Identity,
  Session,
  RegistrationRequest,
  LoginRequest 
} from 'kayan.js';
```
