const crypto = require('crypto');
const WebSocket = require('ws');

/**
 * Authentication module for secure login functionality
 */
class SecureAuth {
  constructor(authServer = 'https://auth.hitboxgames.online') {
    this.authServer = authServer;
    this.ws = null;
    this.sharedSecret = null;
    this.clientKeys = null;
    this.logs = [];
  }

  /**
   * Log messages for debugging
   */
  log(msg) {
    this.logs.push(msg);
    console.log(msg);
  }

  /**
   * Fetch WebSocket URL for login from server
   */
  async fetchLoginWsUrl(uuid) {
    try {
      const res = await fetch(`${this.authServer}/login/init?uuid=${uuid}`);
      const data = await res.json();
      if (!data.wsUrl) throw new Error("No wsUrl in response");
      return data.wsUrl;
    } catch (err) {
      this.log(`❗ Failed to get login wsUrl: ${err.message}`);
      throw err;
    }
  }

  /**
   * Fetch WebSocket URL for register from server
   */
  async fetchRegisterWsUrl(uuid) {
    try {
      const res = await fetch(`${this.authServer}/register/init?uuid=${uuid}`);
      const data = await res.json();
      if (!data.wsUrl) throw new Error("No wsUrl in response");
      return data.wsUrl;
    } catch (err) {
      this.log(`❗ Failed to get register wsUrl: ${err.message}`);
      throw err;
    }
  }

  /**
   * Generate ephemeral ECDH key pair
   */
  async generateEphemeralKey() {
    return await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveBits"]
    );
  }

  /**
   * Export public key to PEM format
   */
  async exportPublicKey(key) {
    const raw = await crypto.subtle.exportKey("spki", key);
    const b64 = Buffer.from(raw).toString('base64');

    const pem = `-----BEGIN PUBLIC KEY-----\n${b64
      .match(/.{1,64}/g)
      .join("\n")}\n-----END PUBLIC KEY-----`;
    return pem;
  }

  /**
   * Import server's public key from base64
   */
  async importServerKey(base64) {
    const raw = Buffer.from(base64, 'base64');
    return await crypto.subtle.importKey(
      "spki",
      raw,
      { name: "ECDH", namedCurve: "P-256" },
      true,
      []
    );
  }

  /**
   * Derive shared secret using ECDH
   */
  async deriveSharedSecret(privKey, pubKey) {
    const sharedBits = await crypto.subtle.deriveBits(
      { name: "ECDH", public: pubKey },
      privKey,
      256
    );

    return await crypto.subtle.importKey(
      "raw",
      sharedBits,
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"]
    );
  }

  /**
   * Encrypt data using AES-GCM
   */
  async encrypt(plain, key) {
    const enc = new TextEncoder();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = enc.encode(plain);

    const ciphertextWithTag = new Uint8Array(
      await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoded)
    );

    const tagLength = 16;
    const ciphertext = ciphertextWithTag.slice(0, -tagLength);
    const tag = ciphertextWithTag.slice(-tagLength);

    return {
      iv: Buffer.from(iv).toString("hex"),
      payload: Buffer.from(ciphertext).toString("hex"),
      tag: Buffer.from(tag).toString("hex"),
    };
  }

  /**
   * Decrypt data using AES-GCM
   */
  async decrypt({ iv, payload, tag }, key) {
    const ivBytes = Uint8Array.from(Buffer.from(iv, "hex"));
    const payloadBytes = Uint8Array.from(Buffer.from(payload, "hex"));
    const tagBytes = Uint8Array.from(Buffer.from(tag, "hex"));

    const fullCiphertext = new Uint8Array(
      payloadBytes.length + tagBytes.length
    );
    fullCiphertext.set(payloadBytes);
    fullCiphertext.set(tagBytes, payloadBytes.length);

    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: ivBytes },
      key,
      fullCiphertext
    );

    return new TextDecoder().decode(decrypted);
  }

  /**
   * Connect to WebSocket server and establish secure channel
   */
  async connectWebSocket(uuid, onMessage, onError, onClose) {
    try {
      const wsUrl = await this.fetchLoginWsUrl(uuid);
      this.clientKeys = await this.generateEphemeralKey();
      const clientPub = await this.exportPublicKey(this.clientKeys.publicKey);

      this.ws = new WebSocket(wsUrl);

      this.ws.on('open', () => {
        this.log("🔌 Securely Connecting To Server...");
        this.ws.send(
          JSON.stringify({ type: "client-public-key", key: clientPub })
        );
      });

      this.ws.on('message', async (data) => {
        try {
          const parsedData = JSON.parse(data.toString());

          if (parsedData.type === "server-public-key") {
            if (typeof parsedData.serverPubKey !== "string") {
              return;
            }
            const serverKey = await this.importServerKey(parsedData.serverPubKey);
            this.sharedSecret = await this.deriveSharedSecret(
              this.clientKeys.privateKey,
              serverKey
            );
            this.log("🔑 End-To-End Encryption Works!");
          } else if (parsedData.payload && parsedData.iv && parsedData.tag) {
            const decryptedRaw = await this.decrypt(
              parsedData,
              this.sharedSecret
            );
            const decrypted = JSON.parse(decryptedRaw);

            this.log("Decrypted message: " + JSON.stringify(decrypted));

            if (onMessage) {
              onMessage(decrypted);
            }
          } else if (parsedData.type === "error") {
            // Sanitize user-supplied error message to prevent log injection
            const sanitizedMessage = typeof parsedData.message === "string"
              ? parsedData.message.replace(/[\r\n]+/g, " ")
              : "";
            this.log(`❗ Error: ${sanitizedMessage}`);
            this.ws.close();
          }
        } catch (err) {
          console.error("❗ Failed to handle message:", err);
          this.log("❗ Failed to handle message: " + JSON.stringify(err));
        }
      });

      this.ws.on('error', (err) => {
        this.log("🚨 Server error");
        if (onError) onError(err);
      });

      this.ws.on('close', () => {
        this.log("❌ Server - Login Portal closed");
        if (onClose) onClose();
      });

    } catch (err) {
      this.log(`❗ End-To-End Encryption setup failed: ${err}`);
      throw err;
    }
  }

  /**
   * Connect to WebSocket server for login and establish secure channel
   */
  async connectForLogin(uuid, onMessage, onError, onClose) {
    try {
      const wsUrl = await this.fetchLoginWsUrl(uuid);
      this.clientKeys = await this.generateEphemeralKey();
      const clientPub = await this.exportPublicKey(this.clientKeys.publicKey);

      this.ws = new WebSocket(wsUrl);

      this.ws.on('open', () => {
        this.log("🔌 Securely Connecting To Login Server...");
        this.ws.send(
          JSON.stringify({ type: "client-public-key", key: clientPub })
        );
      });

      this.ws.on('message', async (data) => {
        try {
          const parsedData = JSON.parse(data.toString());

          if (parsedData.type === "server-public-key") {
            if (typeof parsedData.serverPubKey !== "string") {
              return;
            }
            const serverKey = await this.importServerKey(parsedData.serverPubKey);
            this.sharedSecret = await this.deriveSharedSecret(
              this.clientKeys.privateKey,
              serverKey
            );
            this.log("🔑 End-To-End Encryption Works!");
          } else if (parsedData.payload && parsedData.iv && parsedData.tag) {
            const decryptedRaw = await this.decrypt(
              parsedData,
              this.sharedSecret
            );
            const decrypted = JSON.parse(decryptedRaw);

            this.log("Decrypted message: " + JSON.stringify(decrypted));

            if (onMessage) {
              onMessage(decrypted);
            }
          } else if (parsedData.type === "error") {
            this.log(`❗ Error: ${parsedData.message}`);
            this.ws.close();
          }
        } catch (err) {
          console.error("❗ Failed to handle message:", err);
          this.log("❗ Failed to handle message: " + JSON.stringify(err));
        }
      });

      this.ws.on('error', (err) => {
        this.log("🚨 Login server error");
        if (onError) onError(err);
      });

      this.ws.on('close', () => {
        this.log("❌ Server - Login Portal closed");
        if (onClose) onClose();
      });

    } catch (err) {
      this.log(`❗ Login connection setup failed: ${err}`);
      throw err;
    }
  }

  /**
   * Connect to WebSocket server for registration and establish secure channel
   */
  async connectForRegister(uuid, onMessage, onError, onClose) {
    try {
      const wsUrl = await this.fetchRegisterWsUrl(uuid);
      this.clientKeys = await this.generateEphemeralKey();
      const clientPub = await this.exportPublicKey(this.clientKeys.publicKey);

      this.ws = new WebSocket(wsUrl);

      this.ws.on('open', () => {
        this.log("🔌 Securely Connecting To Register Server...");
        this.ws.send(
          JSON.stringify({ type: "client-public-key", key: clientPub })
        );
      });

      this.ws.on('message', async (data) => {
        try {
          const parsedData = JSON.parse(data.toString());

          if (parsedData.type === "server-public-key") {
            if (typeof parsedData.serverPubKey !== "string") {
              return;
            }
            const serverKey = await this.importServerKey(parsedData.serverPubKey);
            this.sharedSecret = await this.deriveSharedSecret(
              this.clientKeys.privateKey,
              serverKey
            );
            this.log("🔑 End-To-End Encryption Works!");
          } else if (parsedData.payload && parsedData.iv && parsedData.tag) {
            const decryptedRaw = await this.decrypt(
              parsedData,
              this.sharedSecret
            );
            const decrypted = JSON.parse(decryptedRaw);

            this.log("Decrypted message: " + JSON.stringify(decrypted));

            if (onMessage) {
              onMessage(decrypted);
            }
          } else if (parsedData.type === "error") {
            this.log(`❗ Error: ${parsedData.message}`);
            this.ws.close();
          }
        } catch (err) {
          console.error("❗ Failed to handle message:", err);
          this.log("❗ Failed to handle message: " + JSON.stringify(err));
        }
      });

      this.ws.on('error', (err) => {
        this.log("🚨 Register server error");
        if (onError) onError(err);
      });

      this.ws.on('close', () => {
        this.log("❌ Server - Register Portal closed");
        if (onClose) onClose();
      });

    } catch (err) {
      this.log(`❗ Register connection setup failed: ${err}`);
      throw err;
    }
  }

  /**
   * Submit login credentials
   */
  async submitLogin(uuid, username, password) {
    if (!this.ws || !this.sharedSecret) {
      this.log("🔒 Shared secret not ready");
      throw new Error("Shared secret not ready");
    }

    const creds = JSON.stringify({ type: "login", username, password, uuid: uuid });
    const encrypted = await this.encrypt(creds, this.sharedSecret);
    this.ws.send(JSON.stringify(encrypted));
    this.log("📤 Attempting login...");
  }

  /**
   * Submit registration credentials
   */
  async submitRegister(uuid, username, password, email = null) {
    if (!this.ws || !this.sharedSecret) {
      this.log("🔒 Shared secret not ready");
      throw new Error("Shared secret not ready");
    }

    const registrationData = { 
      type: "register", 
      username, 
      password, 
      uuid: uuid 
    };
    
    // Add email if provided
    if (email) {
      registrationData.email = email;
    }

    const creds = JSON.stringify(registrationData);
    const encrypted = await this.encrypt(creds, this.sharedSecret);
    this.ws.send(JSON.stringify(encrypted));
    this.log("📤 Attempting registration...");
  }

  /**
   * Close WebSocket connection
   */
  close() {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }

  /**
   * Get connection status
   */
  isConnected() {
    return this.ws && this.ws.readyState === WebSocket.OPEN;
  }

  /**
   * Get logs
   */
  getLogs() {
    return this.logs;
  }

  /**
   * Clear logs
   */
  clearLogs() {
    this.logs = [];
  }
}

// Export individual functions for standalone use
const cryptoUtils = {
  /**
   * Generate ephemeral ECDH key pair
   */
  generateEphemeralKey: async () => {
    return await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveBits"]
    );
  },

  /**
   * Export public key to PEM format
   */
  exportPublicKey: async (key) => {
    const raw = await crypto.subtle.exportKey("spki", key);
    const b64 = Buffer.from(raw).toString('base64');
    return `-----BEGIN PUBLIC KEY-----\n${b64
      .match(/.{1,64}/g)
      .join("\n")}\n-----END PUBLIC KEY-----`;
  },

  /**
   * Import public key from base64
   */
  importPublicKey: async (base64) => {
    const raw = Buffer.from(base64, 'base64');
    return await crypto.subtle.importKey(
      "spki",
      raw,
      { name: "ECDH", namedCurve: "P-256" },
      true,
      []
    );
  },

  /**
   * Derive shared secret using ECDH
   */
  deriveSharedSecret: async (privKey, pubKey) => {
    const sharedBits = await crypto.subtle.deriveBits(
      { name: "ECDH", public: pubKey },
      privKey,
      256
    );

    return await crypto.subtle.importKey(
      "raw",
      sharedBits,
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"]
    );
  },

  /**
   * Encrypt data using AES-GCM
   */
  encrypt: async (plain, key) => {
    const enc = new TextEncoder();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = enc.encode(plain);

    const ciphertextWithTag = new Uint8Array(
      await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoded)
    );

    const tagLength = 16;
    const ciphertext = ciphertextWithTag.slice(0, -tagLength);
    const tag = ciphertextWithTag.slice(-tagLength);

    return {
      iv: Buffer.from(iv).toString("hex"),
      payload: Buffer.from(ciphertext).toString("hex"),
      tag: Buffer.from(tag).toString("hex"),
    };
  },

  /**
   * Decrypt data using AES-GCM
   */
  decrypt: async ({ iv, payload, tag }, key) => {
    const ivBytes = Uint8Array.from(Buffer.from(iv, "hex"));
    const payloadBytes = Uint8Array.from(Buffer.from(payload, "hex"));
    const tagBytes = Uint8Array.from(Buffer.from(tag, "hex"));

    const fullCiphertext = new Uint8Array(
      payloadBytes.length + tagBytes.length
    );
    fullCiphertext.set(payloadBytes);
    fullCiphertext.set(tagBytes, payloadBytes.length);

    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: ivBytes },
      key,
      fullCiphertext
    );

    return new TextDecoder().decode(decrypted);
  }
};

// Export the main class and utility functions
module.exports = {
  SecureAuth,
  cryptoUtils,
  
  // Convenience exports
  generateEphemeralKey: cryptoUtils.generateEphemeralKey,
  exportPublicKey: cryptoUtils.exportPublicKey,
  importPublicKey: cryptoUtils.importPublicKey,
  deriveSharedSecret: cryptoUtils.deriveSharedSecret,
  encrypt: cryptoUtils.encrypt,
  decrypt: cryptoUtils.decrypt
}; 