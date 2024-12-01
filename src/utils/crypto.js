import crypto from 'crypto';

/**
 * Derives a key from the password using PBKDF2 with the provided parameters.
 * @param {string} password - The password used for key derivation.
 * @param {Buffer} salt - The salt used in the key derivation.
 * @param {number} iterations - The number of iterations for PBKDF2.
 * @param {number} keyLength - The length of the derived key.
 * @returns {Buffer} The derived key.
 */
function deriveKey(password, salt, iterations, keyLength) {
    return crypto.pbkdf2Sync(password, salt, iterations, keyLength, 'sha256');
}

/**
 * Encrypts a given text using a password with specified parameters.
 * @param {string} password - The password for encryption.
 * @param {string} text - The text to encrypt.
 * @param {number} saltLength - The length of the salt to generate.
 * @param {number} ivLength - The length of the initialization vector (IV) to generate.
 * @param {string} algorithm - The encryption algorithm to use.
 * @param {number} iterations - The number of iterations for PBKDF2.
 * @param {number} keyLength - The length of the key used in encryption.
 * @returns {string} The encrypted text with salt, IV, and authentication tag (for GCM) concatenated.
 */
function encrypt(password, text, saltLength, ivLength, algorithm, iterations, keyLength) {
    // Validate input
    if (!text) {
        throw new Error('Text to encrypt cannot be empty');
    }

    const salt = crypto.randomBytes(Number(saltLength));  // Generate random salt
    const iv = crypto.randomBytes(Number(ivLength));  // Generate random IV

    // Validate algorithm parameters
    validateAlgorithmParameters(algorithm, keyLength, ivLength);

    const key = deriveKey(password, salt, Number(iterations), Number(keyLength));  // Derive encryption key

    // Create cipher
    const cipher = crypto.createCipheriv(algorithm, key, iv);

    let encrypted, authTag;
    if (algorithm.includes('gcm')) {
        // For GCM modes
        encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        authTag = cipher.getAuthTag();

        // Return salt:iv:encrypted:tag
        return `${salt.toString('hex')}:${iv.toString('hex')}:${encrypted}:${authTag.toString('hex')}`;
    } else {
        // For CBC modes
        encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');

        // Return salt:iv:encrypted
        return `${salt.toString('hex')}:${iv.toString('hex')}:${encrypted}`;
    }
}

/**
 * Decrypts the given encrypted text using the password with specified parameters.
 * @param {string} password - The password for decryption.
 * @param {string} encryptedText - The encrypted text with salt and IV.
 * @param {string} algorithm - The encryption algorithm to use.
 * @param {number} iterations - The number of iterations for PBKDF2.
 * @param {number} keyLength - The length of the key used in decryption.
 * @returns {string} The decrypted text.
 */
function decrypt(password, encryptedText, algorithm, iterations, keyLength) {
    // Split the input differently for GCM and CBC modes
    const parts = encryptedText.split(':');
    if (parts.length < 3) {
        throw new Error('Invalid encrypted text format');
    }

    const salt = Buffer.from(parts[0], 'hex');
    const iv = Buffer.from(parts[1], 'hex');
    const encrypted = parts[2];
    const tag = parts.length > 3 ? Buffer.from(parts[3], 'hex') : undefined;

    // Validate algorithm parameters
    validateAlgorithmParameters(algorithm, keyLength, iv.length);

    const key = deriveKey(password, salt, Number(iterations), Number(keyLength));  // Derive decryption key

    let decrypted;
    if (algorithm.includes('gcm')) {
        // For GCM modes
        const decipher = crypto.createDecipheriv(algorithm, key, iv);
        
        // Ensure we have a tag for GCM mode
        if (!tag) {
            throw new Error('Authentication tag is required for GCM decryption');
        }
        
        decipher.setAuthTag(tag);
        decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
    } else {
        // For CBC modes
        const decipher = crypto.createDecipheriv(algorithm, key, iv);
        decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
    }

    return decrypted;
}

/**
 * Validates the algorithm parameters for encryption/decryption.
 * @param {string} algorithm - The encryption algorithm to validate.
 * @param {number} keyLength - The length of the key.
 * @param {number} ivLength - The length of the initialization vector.
 * @throws {Error} If the algorithm parameters are invalid.
 */
function validateAlgorithmParameters(algorithm, keyLength, ivLength) {
    const algorithmSpecs = {
        'aes-256-cbc': { keyLength: 32, ivLength: 16 },
        'aes-256-gcm': { keyLength: 32, ivLength: 12 },
        'aes-128-gcm': { keyLength: 16, ivLength: 12 },
        'aes-128-cbc': { keyLength: 16, ivLength: 16 },
        'aes-192-cbc': { keyLength: 24, ivLength: 16 },
        'aes-192-gcm': { keyLength: 24, ivLength: 12 }
    };

    const spec = algorithmSpecs[algorithm];
    if (!spec) {
        throw new Error('Invalid encryption algorithm');
    }

    if (keyLength !== spec.keyLength) {
        throw new Error(`${algorithm} requires a ${spec.keyLength}-byte key length.`);
    }

    if (ivLength !== spec.ivLength) {
        throw new Error(`${algorithm} requires a ${spec.ivLength}-byte IV length.`);
    }
}

export { encrypt, decrypt };