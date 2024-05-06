
```javascript
// Function to encrypt a string with a password
async function encrypt(str, password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(str);

  const passwordData = encoder.encode(password);
  const key = await crypto.subtle.importKey("raw", passwordData, "PBKDF2", false, ["deriveBits", "deriveKey"]);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const derivedKey = await crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, key, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);

  const cipherText = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, derivedKey, data);
  const encryptedData = new Uint8Array([...salt, ...iv, ...new Uint8Array(cipherText)]);

  return encryptedData;
}

// Function to decrypt an encrypted string with a password
async function decrypt(encryptedData, password) {
  const decoder = new TextDecoder();
  const passwordData = new TextEncoder().encode(password);
  const key = await crypto.subtle.importKey("raw", passwordData, { name: "PBKDF2" }, false, ["deriveBits", "deriveKey"]);

  const salt = encryptedData.slice(0, 16);
  const iv = encryptedData.slice(16, 28);
  const cipherText = encryptedData.slice(28);
  const derivedKey = await crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, key, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);

  const decryptedData = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, derivedKey, cipherText);
  return decoder.decode(decryptedData);
}

async function test() {
  const password = "myPassword";
  const plaintext = "This is a secret message.";

  // Encrypt the plaintext with the password
  const encryptedData = await encrypt(plaintext, password);
  console.log(`Encrypted data: ${encryptedData}`);

  // Decrypt the encrypted data with the password
  const decryptedText = await decrypt(encryptedData, password);
  console.log(`Decrypted text: ${decryptedText}`);
}

test();
```