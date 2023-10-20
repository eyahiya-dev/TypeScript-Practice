import * as crypto from 'crypto';

// Encryption
function encrypt(text: string, secretKey: string): string {
  const cipher = crypto.createCipher('aes-256-cbc', secretKey);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

// Decryption
function decrypt(encryptedText: string, secretKey: string): string {
  const decipher = crypto.createDecipher('aes-256-cbc', secretKey);
  let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

const secretKey = 'YourSecretKey'; // Replace with your secret key
const plaintext = 'Hello, World!';

const encryptedText = encrypt(plaintext, secretKey);
console.log('Encrypted Text:', encryptedText);

const decryptedText = decrypt(encryptedText, secretKey);
console.log('Decrypted Text:', decryptedText);
