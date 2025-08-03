const { SecureAuth, cryptoUtils } = require('./auth');
const crypto = require('crypto');

/**
 * Example usage of the SecureAuth module
 */
async function exampleUsage() {
  // Example 1: Using default localhost server
  console.log('=== Example 1: Default Localhost Server ===');
  const auth1 = new SecureAuth(); // Uses default http://localhost:3001
  
  // Example 2: Using custom auth server
  console.log('=== Example 2: Custom Auth Server ===');
  const auth2 = new SecureAuth('https://auth.hitboxgames.online');
  
  // Example 3: Using separate login and register functions
  console.log('=== Example 3: Separate Login and Register Functions ===');
  
  try {
    // Generate UUID for this session
    const uuid = crypto.randomUUID();
    console.log('🆔 Generated UUID:', uuid);
    
    // Connect for login using custom auth server
    await auth2.connectForLogin(uuid,
      // onMessage callback
      (decryptedMessage) => {
        console.log('Login response:', decryptedMessage);
        if (decryptedMessage.type === 'success') {
          console.log(`✅ Login successful: ${decryptedMessage.message}`);
        }
      },
      // onError callback
      (error) => {
        console.error('Login WebSocket error:', error);
      },
      // onClose callback
      () => {
        console.log('Login WebSocket connection closed');
      }
    );

    // Wait a moment for connection to establish
    await new Promise(resolve => setTimeout(resolve, 1000));

    // Submit login credentials
    if (auth2.isConnected()) {
      await auth2.submitLogin(uuid, 'testuser', 'testpassword');
    }

    // Get logs
    console.log('Login logs:', auth2.getLogs());

  } catch (error) {
    console.error('Login error:', error);
  } finally {
    // Clean up
    auth1.close();
    auth2.close();
  }
}

/**
 * Example 2: Registration Flow
 */
async function registrationExample() {
  console.log('\n=== Example 2: Registration Flow ===');
  
  const auth = new SecureAuth('https://auth.hitboxgames.online');
  
  try {
    // Generate UUID for this session
    const uuid = crypto.randomUUID();
    console.log('🆔 Generated UUID:', uuid);
    
    // Connect to WebSocket server for registration
    await auth.connectForRegister(uuid,
      // onMessage callback
      (decryptedMessage) => {
        console.log('Registration response:', decryptedMessage);
        if (decryptedMessage.type === 'success') {
          console.log(`✅ Registration successful: ${decryptedMessage.message}`);
        } else if (decryptedMessage.type === 'error') {
          console.log(`❌ Registration failed: ${decryptedMessage.message}`);
        }
      },
      // onError callback
      (error) => {
        console.error('Register WebSocket error:', error);
      },
      // onClose callback
      () => {
        console.log('Register WebSocket connection closed');
      }
    );

    // Wait a moment for connection to establish
    await new Promise(resolve => setTimeout(resolve, 1000));

    // Submit registration credentials
    if (auth.isConnected()) {
      await auth.submitRegister(uuid, 'newuser123', 'securepassword123', 'newuser@example.com');
    }

    // Get logs
    console.log('Registration logs:', auth.getLogs());

  } catch (error) {
    console.error('Registration error:', error);
  } finally {
    // Clean up
    auth.close();
  }
}

/**
 * Example 3: Complete Login and Register Flow
 */
async function completeFlowExample() {
  console.log('\n=== Example 3: Complete Login and Register Flow ===');
  
  const auth = new SecureAuth(); // Uses localhost:3001
  
  try {
    // Generate UUID for this session
    const uuid = crypto.randomUUID();
    console.log('🆔 Generated UUID:', uuid);
    
    // First, try to register a new user
    console.log('📝 Step 1: Registering new user...');
    await auth.connectForRegister(uuid,
      (message) => {
        console.log('Register response:', message);
        if (message.type === 'success') {
          console.log('✅ Registration successful, now trying to login...');
          // After successful registration, try to login
          setTimeout(async () => {
            try {
              await auth.close(); // Close register connection
              await auth.connectForLogin(uuid,
                (loginMessage) => {
                  console.log('Login response:', loginMessage);
                  if (loginMessage.type === 'success') {
                    console.log('✅ Login successful!');
                  }
                },
                (error) => console.error('Login error:', error),
                () => console.log('Login connection closed')
              );
              
              await new Promise(resolve => setTimeout(resolve, 1000));
              if (auth.isConnected()) {
                await auth.submitLogin(uuid, 'newuser123', 'securepassword123');
              }
            } catch (error) {
              console.error('Login attempt failed:', error);
            }
          }, 1000);
        }
      },
      (error) => console.error('Register error:', error),
      () => console.log('Register connection closed')
    );

    await new Promise(resolve => setTimeout(resolve, 1000));
    if (auth.isConnected()) {
      await auth.submitRegister(uuid, 'newuser123', 'securepassword123', 'newuser@example.com');
    }

    // Wait for the flow to complete
    await new Promise(resolve => setTimeout(resolve, 5000));

  } catch (error) {
    console.error('Complete flow error:', error);
  } finally {
    auth.close();
  }
}

/**
 * Example 4: Using individual crypto functions
 */
async function cryptoExample() {
  console.log('\n=== Example 4: Individual Crypto Functions ===');
  
  try {
    // Generate a new UUID
    const uuid = crypto.randomUUID();
    console.log('Generated UUID:', uuid);

    // Generate ephemeral key pair
    const keyPair = await cryptoUtils.generateEphemeralKey();
    console.log('Generated key pair:', keyPair);

    // Export public key
    const publicKeyPem = await cryptoUtils.exportPublicKey(keyPair.publicKey);
    console.log('Public key (PEM):', publicKeyPem);

    // Example encryption/decryption
    const testData = 'Hello, secure world!';
    const testKey = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );

    const encrypted = await cryptoUtils.encrypt(testData, testKey);
    console.log('Encrypted data:', encrypted);

    const decrypted = await cryptoUtils.decrypt(encrypted, testKey);
    console.log('Decrypted data:', decrypted);

  } catch (error) {
    console.error('Crypto error:', error);
  }
}

/**
 * Example 5: Standalone function usage
 */
async function standaloneExample() {
  console.log('\n=== Example 5: Standalone Functions ===');
  
  const { 
    generateEphemeralKey, 
    exportPublicKey,
    encrypt,
    decrypt 
  } = require('./auth');

  try {
    // Use functions directly
    const uuid = crypto.randomUUID();
    console.log('Standalone UUID:', uuid);

    const keyPair = await generateEphemeralKey();
    const pubKey = await exportPublicKey(keyPair.publicKey);
    console.log('Standalone public key:', pubKey.substring(0, 50) + '...');

  } catch (error) {
    console.error('Standalone function error:', error);
  }
}

// Run examples
async function runExamples() {
  console.log('🔐 Secure Auth Module Examples\n');
  
  await exampleUsage();
  await registrationExample();
  await completeFlowExample();
  await cryptoExample();
  await standaloneExample();
  
  console.log('\n✅ Examples completed!');
}

// Export for use in other files
module.exports = {
  exampleUsage,
  registrationExample,
  completeFlowExample,
  cryptoExample,
  standaloneExample,
  runExamples
};

// Run if this file is executed directly
if (require.main === module) {
  runExamples().catch(console.error);
} 