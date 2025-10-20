/**
 * Handles packet encryption using AES-256-GCM with ECDH key exchange.
 * Provides authenticated encryption to prevent sniffing, injection, and tampering.
 * Uses Web Crypto API for browser-native cryptographic operations.
 */
export class PacketEncryption
{
    private static readonly AES_KEY_SIZE = 256;
    private static readonly NONCE_SIZE = 12; // GCM standard
    private static readonly TAG_SIZE = 16; // GCM authentication tag
    
    private _ecdhKeyPair: CryptoKeyPair | null = null;
    private _aesKey: CryptoKey | null = null;
    private _isInitialized: boolean = false;
    private _nonceCounter: number = 0;

    /**
     * Initialize ECDH key pair for key exchange
     */
    public async initialize(): Promise<void>
    {
        try
        {
            // Generate ECDH key pair using P-256 curve (same as server)
            this._ecdhKeyPair = await window.crypto.subtle.generateKey(
                {
                    name: 'ECDH',
                    namedCurve: 'P-256'
                },
                false, // not extractable for security
                ['deriveKey', 'deriveBits']
            );
        }
        catch (error)
        {
            throw new Error('Failed to initialize encryption: ' + error);
        }
    }

    /**
     * Gets the client's public key for key exchange (DER format)
     */
    public async getPublicKey(): Promise<ArrayBuffer>
    {
        if (!this._ecdhKeyPair)
        {
            throw new Error('Encryption not initialized');
        }

        return await window.crypto.subtle.exportKey('spki', this._ecdhKeyPair.publicKey);
    }

    /**
     * Completes key exchange with server's public key and derives shared secret
     */
    public async completeKeyExchange(serverPublicKeyBytes: ArrayBuffer): Promise<void>
    {
        try
        {
            if (!this._ecdhKeyPair)
            {
                throw new Error('Encryption not initialized');
            }

            // Import server's public key
            const serverPublicKey = await window.crypto.subtle.importKey(
                'spki',
                serverPublicKeyBytes,
                {
                    name: 'ECDH',
                    namedCurve: 'P-256'
                },
                false,
                []
            );

            // Derive AES key from shared secret using ECDH
            this._aesKey = await window.crypto.subtle.deriveKey(
                {
                    name: 'ECDH',
                    public: serverPublicKey
                },
                this._ecdhKeyPair.privateKey,
                {
                    name: 'AES-GCM',
                    length: PacketEncryption.AES_KEY_SIZE
                },
                false, // Not extractable for security
                ['encrypt', 'decrypt']
            );

            this._isInitialized = true;
            this._nonceCounter = 0;
        }
        catch (error)
        {
            throw new Error('Failed to complete key exchange: ' + error);
        }
    }

    /**
     * Generates a unique nonce for each packet
     * Uses counter + random to ensure uniqueness and prevent replay attacks
     */
    private generateNonce(): Uint8Array
    {
        this._nonceCounter++;
        const nonce = new Uint8Array(PacketEncryption.NONCE_SIZE);
        
        // First 8 bytes: counter (prevents reuse)
        const counterView = new DataView(nonce.buffer, 0, 8);
        counterView.setBigUint64(0, BigInt(this._nonceCounter), true);
        
        // Last 4 bytes: random (additional entropy)
        const randomBytes = new Uint8Array(4);
        window.crypto.getRandomValues(randomBytes);
        nonce.set(randomBytes, 8);
        
        return nonce;
    }

    /**
     * Encrypts packet data using AES-256-GCM
     * Format: [12-byte nonce][encrypted data][16-byte auth tag]
     * The auth tag is automatically appended by AES-GCM
     */
    public async encrypt(plaintext: ArrayBuffer): Promise<ArrayBuffer>
    {
        if (!this._isInitialized || !this._aesKey)
        {
            throw new Error('Encryption not initialized. Complete key exchange first.');
        }

        if (!plaintext || plaintext.byteLength === 0)
        {
            throw new Error('Plaintext cannot be null or empty');
        }

        const nonce = this.generateNonce();

        try
        {
            // AES-GCM automatically appends the authentication tag
            const ciphertext = await window.crypto.subtle.encrypt(
                {
                    name: 'AES-GCM',
                    iv: nonce,
                    tagLength: PacketEncryption.TAG_SIZE * 8 // in bits
                },
                this._aesKey,
                plaintext
            );

            // Combine: nonce + (ciphertext + tag)
            const result = new Uint8Array(PacketEncryption.NONCE_SIZE + ciphertext.byteLength);
            result.set(nonce, 0);
            result.set(new Uint8Array(ciphertext), PacketEncryption.NONCE_SIZE);

            return result.buffer;
        }
        catch (error)
        {
            throw new Error('Encryption failed: ' + error);
        }
    }

    /**
     * Decrypts packet data using AES-256-GCM
     * Throws exception if authentication fails (tampered data)
     */
    public async decrypt(encryptedData: ArrayBuffer): Promise<ArrayBuffer>
    {
        if (!this._isInitialized || !this._aesKey)
        {
            throw new Error('Decryption not initialized. Complete key exchange first.');
        }

        if (!encryptedData || encryptedData.byteLength < PacketEncryption.NONCE_SIZE + PacketEncryption.TAG_SIZE)
        {
            throw new Error('Invalid encrypted data');
        }

        const dataView = new Uint8Array(encryptedData);

        // Extract nonce
        const nonce = dataView.slice(0, PacketEncryption.NONCE_SIZE);

        // Extract ciphertext + tag (AES-GCM handles tag automatically)
        const ciphertextWithTag = dataView.slice(PacketEncryption.NONCE_SIZE);

        try
        {
            // AES-GCM automatically verifies the authentication tag
            const plaintext = await window.crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: nonce,
                    tagLength: PacketEncryption.TAG_SIZE * 8 // in bits
                },
                this._aesKey,
                ciphertextWithTag
            );

            return plaintext;
        }
        catch (error)
        {
            throw new Error('Decryption failed: data has been tampered with or corrupted');
        }
    }

    /**
     * Check if encryption is ready to use
     */
    public get isInitialized(): boolean
    {
        return this._isInitialized;
    }

    /**
     * Cleanup resources
     */
    public dispose(): void
    {
        this._ecdhKeyPair = null;
        this._aesKey = null;
        this._isInitialized = false;
        this._nonceCounter = 0;
    }
}

