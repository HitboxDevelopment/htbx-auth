# Secure Auth Module

A Node.js module providing secure authentication with end-to-end encryption using WebSocket connections and cryptographic functions.

## Features

- 🔐 **End-to-End Encryption**: Uses ECDH key exchange and AES-GCM encryption
- 🌐 **WebSocket Communication**: Secure real-time communication with authentication server
- 🔑 **Ephemeral Key Generation**: Fresh key pairs for each session
- 📝 **Comprehensive Logging**: Built-in logging for debugging and monitoring
- 🛠️ **Modular Design**: Use as a complete class or individual functions

## Installation

```bash
npm install ws
```

## Quick Start

### Using the SecureAuth Class

```javascript
const { SecureAuth } = require('./auth');

async function login() {
  // Use default localhost server
  const auth = new SecureAuth();
  
  // Or specify a custom auth server
  const auth = new SecureAuth('https://auth.hitboxgames.online');
  
  try {
    // Connect for login
    await auth.connectForLogin(
      (message) => {
        if (message.type === 'success') {
          console.log('Login successful!');
        }
      },
      (error) => console.error('Error:', error),
      () => console.log('Connection closed')
    );
    
    // Submit login credentials
    await auth.submitLogin('username', 'password');
    
    // Or connect for registration
    await auth.connectForRegister(
      (message) => {
        if (message.type === 'success') {
          console.log('Registration successful!');
        }
      },
      (error) => console.error('Error:', error),
      () => console.log('Connection closed')
    );
    
    // Submit registration credentials
    await auth.submitRegister('newuser', 'password', 'user@example.com');
    
  } catch (error) {
    console.error('Authentication failed:', error);
  } finally {
    auth.close();
  }
}
```
### Registration Example

```javascript
const { SecureAuth } = require('./auth');

async function register() {
  const auth = new SecureAuth('https://auth.hitboxgames.online');
  
  try {
    await auth.connectForRegister(
      (message) => {
        if (message.type === 'success') {
          console.log('Registration successful!');
        } else if (message.type === 'error') {
          console.log('Registration failed:', message.message);
        }
      },
      (error) => console.error('Error:', error),
      () => console.log('Connection closed')
    );
    
    // Submit registration with email
    await auth.submitRegister('newuser', 'password123', 'user@example.com');
    
    // Or submit registration without email
    await auth.submitRegister('anotheruser', 'password123');
    
  } catch (error) {
    console.error('Registration failed:', error);
  } finally {
    auth.close();
  }
}
```

### Using Individual Functions

```javascript
const { encrypt, decrypt } = require('./auth');
const crypto = require('crypto');

// Generate a UUID
const uuid = crypto.randomUUID();

// Encrypt/decrypt data
const key = await crypto.subtle.generateKey(
  { name: "AES-GCM" },
  false,
  ["encrypt", "decrypt"]
);

const encrypted = await encrypt('secret data', key);
const decrypted = await decrypt(encrypted, key);
```

## API Reference

### SecureAuth Class

#### Constructor

```javascript
// Use default localhost server
const auth = new SecureAuth();

// Or specify a custom auth server
const auth = new SecureAuth('https://auth.hitboxgames.online');
```

**Parameters:**

- `authServer` (string, optional): The authentication server URL. Defaults to `'http://localhost:3001'`.

#### Methods

##### `connectWebSocket(uuid, onMessage, onError, onClose)`

Establishes a secure WebSocket connection to the authentication server (legacy method, uses login endpoint).

- `uuid` (string): The UUID for this session
- `onMessage(message)`: Callback for received messages
- `onError(error)`: Callback for connection errors
- `onClose()`: Callback when connection closes

##### `connectForLogin(uuid, onMessage, onError, onClose)`

Establishes a secure WebSocket connection to the login server endpoint.

- `uuid` (string): The UUID for this session
- `onMessage(message)`: Callback for received messages
- `onError(error)`: Callback for connection errors
- `onClose()`: Callback when connection closes

##### `connectForRegister(uuid, onMessage, onError, onClose)`

Establishes a secure WebSocket connection to the register server endpoint.

- `uuid` (string): The UUID for this session
- `onMessage(message)`: Callback for received messages
- `onError(error)`: Callback for connection errors
- `onClose()`: Callback when connection closes

##### `submitLogin(uuid, username, password)`

Submits login credentials securely.

- `uuid` (string): The UUID for this session
- `username` (string): The username for login
- `password` (string): The password for login

##### `submitRegister(uuid, username, password, email)`

Submits registration credentials securely.

- `uuid` (string): The UUID for this session
- `username` (string): The username for registration
- `password` (string): The password for registration  
- `email` (string, optional): The email address for registration

##### `close()`

Closes the WebSocket connection.

##### `isConnected()`

Returns `true` if connected to the server.

##### `getLogs()`

Returns array of log messages.

##### `clearLogs()`

Clears the log array.

### Crypto Utilities

#### `generateEphemeralKey()`

Generates an ECDH key pair for secure key exchange.

Generates an ECDH key pair for secure key exchange.

#### `exportPublicKey(key)`

Exports a public key to PEM format.

#### `importPublicKey(base64)`

Imports a public key from base64 format.

#### `deriveSharedSecret(privateKey, publicKey)`

Derives a shared secret using ECDH.

#### `encrypt(plaintext, key)`

Encrypts data using AES-GCM.

#### `decrypt(encryptedData, key)`

Decrypts data using AES-GCM.

## Configuration

The module can connect to any authentication server with the following endpoints:

- `GET /login/init?uuid={uuid}` - Returns WebSocket URL for login
- `GET /register/init?uuid={uuid}` - Returns WebSocket URL for registration
- WebSocket endpoints for secure communication

**Default Configuration:**

- Default server: `http://localhost:3001`
- Can be overridden by passing a custom URL to the constructor

**Example:**

```javascript
// Use default localhost server
const auth = new SecureAuth();

// Use custom auth server
const auth = new SecureAuth('https://auth.hitboxgames.online');
```

## Security Features

- **ECDH Key Exchange**: Secure key agreement protocol
- **AES-GCM Encryption**: Authenticated encryption for data protection
- **Ephemeral Keys**: Fresh keys for each session
- **UUID-based Sessions**: Unique session identifiers
- **End-to-End Encryption**: Server cannot decrypt user data

## Error Handling

The module provides comprehensive error handling:

```javascript
try {
  await auth.connectWebSocket();
} catch (error) {
  console.error('Connection failed:', error.message);
  // Handle specific error types
  if (error.message.includes('wsUrl')) {
    // Server not available
  }
}
```

## Logging

Built-in logging system for debugging:

```javascript
const logs = auth.getLogs();
console.log('Authentication logs:', logs);
```

## Examples

See `auth-example.js` for complete usage examples including:

1. Complete login flow
2. Registration flow
3. Individual crypto function usage
4. Standalone function examples

## Requirements

- Node.js >= 16.0.0
- `ws` package for WebSocket support
- Authentication server with the required endpoints (defaults to localhost:3001)

## License

MIT License - see LICENSE file for details.
