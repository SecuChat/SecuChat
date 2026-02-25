const KeyStore = {
    DB_NAME: 'secuchat',
    STORE_NAME: 'keys',
    db: null,

    async init() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open(this.DB_NAME, 1);
            request.onerror = () => reject(request.error);
            request.onsuccess = () => {
                this.db = request.result;
                resolve();
            };
            request.onupgradeneeded = (e) => {
                e.target.result.createObjectStore(this.STORE_NAME);
            };
        });
    },

    async get(key) {
        return new Promise((resolve, reject) => {
            const tx = this.db.transaction(this.STORE_NAME, 'readonly');
            const request = tx.objectStore(this.STORE_NAME).get(key);
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
    },

    async set(key, value) {
        return new Promise((resolve, reject) => {
            const tx = this.db.transaction(this.STORE_NAME, 'readwrite');
            const request = tx.objectStore(this.STORE_NAME).put(value, key);
            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
    },

    async delete(key) {
        return new Promise((resolve, reject) => {
            const tx = this.db.transaction(this.STORE_NAME, 'readwrite');
            const request = tx.objectStore(this.STORE_NAME).delete(key);
            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
    }
};

class RoomRatchet {
    constructor(roomId) {
        this.roomId = roomId || '';
        this.generation = 0;
        this.rootKey = null;
        this.chainKey = null;
        this.messageNum = 0;
        this.skippedKeys = new Map();
        this.MAX_SKIPPED = 100;
    }

    async hkdf(input, salt, info) {
        const encoder = new TextEncoder();
        const inputKey = await window.crypto.subtle.importKey(
            'raw',
            input,
            { name: 'HKDF' },
            false,
            ['deriveBits']
        );
        const infoBytes = encoder.encode(info);
        const bits = await window.crypto.subtle.deriveBits(
            {
                name: 'HKDF',
                hash: 'SHA-256',
                salt: salt,
                info: infoBytes
            },
            inputKey,
            256
        );
        return new Uint8Array(bits);
    }

    async init() {
        const rootKey = window.crypto.getRandomValues(new Uint8Array(32));
        await this.initFromRootKey(rootKey);
        return rootKey;
    }

    roomSalt() {
        return new TextEncoder().encode('secuchat:room:' + this.roomId);
    }

    async initFromRootKey(rootKey) {
        this.rootKey = rootKey;
        this.chainKey = await this.hkdf(rootKey, this.roomSalt(), 'chain');
        this.messageNum = 0;
        this.generation++;
        this.skippedKeys.clear();
    }

    async nextMessageKey() {
        const currentMessageNum = this.messageNum;
        const salt = this.roomSalt();
        const messageKey = await this.hkdf(this.chainKey, salt, 'msg');
        const key = await window.crypto.subtle.importKey(
            'raw',
            messageKey,
            { name: 'AES-GCM' },
            false,
            ['encrypt', 'decrypt']
        );
        this.chainKey = await this.hkdf(this.chainKey, salt, 'next');
        this.messageNum++;
        return {
            key,
            messageNum: currentMessageNum,
            generation: this.generation
        };
    }

    async advanceChain() {
        this.chainKey = await this.hkdf(this.chainKey, this.roomSalt(), 'next');
        this.messageNum++;
    }

    async getMessageKey(num) {
        const salt = this.roomSalt();
        let chainKey = this.chainKey;
        for (let i = this.messageNum; i < num; i++) {
            chainKey = await this.hkdf(chainKey, salt, 'next');
        }
        const messageKey = await this.hkdf(chainKey, salt, 'msg');
        return await window.crypto.subtle.importKey(
            'raw',
            messageKey,
            { name: 'AES-GCM' },
            false,
            ['encrypt', 'decrypt']
        );
    }

    async decryptMessage(generation, messageNum, iv, ciphertext) {
        if (generation !== this.generation) {
            throw new Error(`Generation mismatch: expected ${this.generation}, got ${generation}`);
        }

        if (messageNum < this.messageNum - this.MAX_SKIPPED) {
            throw new Error('Message too old');
        }

        while (this.messageNum < messageNum) {
            const skippedKey = await this.getMessageKey(this.messageNum);
            this.skippedKeys.set(this.messageNum, skippedKey);
            await this.advanceChain();
            if (this.skippedKeys.size > this.MAX_SKIPPED) {
                let oldestNum = Infinity;
                for (const num of this.skippedKeys.keys()) {
                    if (num < oldestNum) oldestNum = num;
                }
                if (oldestNum !== Infinity) this.skippedKeys.delete(oldestNum);
            }
        }

        let key;
        if (this.skippedKeys.has(messageNum)) {
            key = this.skippedKeys.get(messageNum);
            this.skippedKeys.delete(messageNum);
        } else {
            key = await this.getMessageKey(messageNum);
            await this.advanceChain();
        }

        const aad = new TextEncoder().encode(JSON.stringify({
            room_id: this.roomId,
            generation: generation,
            message_num: messageNum
        }));
        const decrypted = await window.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv, additionalData: aad },
            key,
            ciphertext
        );
        return new TextDecoder().decode(decrypted);
    }

    getState() {
        return {
            generation: this.generation,
            messageNum: this.messageNum,
            rootKey: Array.from(this.rootKey),
            chainKey: Array.from(this.chainKey)
        };
    }

    async setState(state) {
        this.generation = state.generation;
        this.messageNum = state.messageNum;
        this.rootKey = new Uint8Array(state.rootKey);
        this.chainKey = new Uint8Array(state.chainKey);
        this.skippedKeys.clear();
    }
}

const Crypto = {
    keyPair: null,
    signingKeyPair: null,
    pendingKeyPair: null,
    pendingSigningKeyPair: null,
    roomRatchets: {},
    PBKDF2_ITERATIONS: 600000,
    LEGACY_PBKDF2_ITERATIONS: 100000,
    STORAGE_KEY: 'secuchat_keys',

    bytesToBase64(bytes) {
        if (!bytes) return '';
        let u8;
        if (bytes instanceof Uint8Array) {
            u8 = bytes;
        } else if (bytes instanceof ArrayBuffer) {
            u8 = new Uint8Array(bytes);
        } else if (Array.isArray(bytes)) {
            u8 = new Uint8Array(bytes);
        } else {
            return '';
        }

        let binary = '';
        const chunkSize = 0x2000;
        for (let i = 0; i < u8.length; i += chunkSize) {
            binary += String.fromCharCode.apply(null, u8.subarray(i, i + chunkSize));
        }
        return btoa(binary);
    },

    base64ToBytes(value) {
        if (!value) return new Uint8Array();
        if (value instanceof Uint8Array) return value;
        if (Array.isArray(value)) return new Uint8Array(value);
        if (typeof value !== 'string') return new Uint8Array();

        try {
            const binary = atob(value);
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) {
                bytes[i] = binary.charCodeAt(i);
            }
            return bytes;
        } catch {
            return new Uint8Array();
        }
    },

    async init() {
        await KeyStore.init();
    },

    async generateKeyPair() {
        this.keyPair = await window.crypto.subtle.generateKey(
            {
                name: 'ECDH',
                namedCurve: 'P-256'
            },
            true,
            ['deriveKey', 'deriveBits']
        );
        return this.keyPair;
    },

    async generateKeyPairStandalone() {
        return await window.crypto.subtle.generateKey(
            {
                name: 'ECDH',
                namedCurve: 'P-256'
            },
            true,
            ['deriveKey', 'deriveBits']
        );
    },

    async generateSigningKeyPair() {
        this.signingKeyPair = await window.crypto.subtle.generateKey(
            {
                name: 'ECDSA',
                namedCurve: 'P-256'
            },
            true,
            ['sign', 'verify']
        );
        return this.signingKeyPair;
    },

    async generateSigningKeyPairStandalone() {
        return await window.crypto.subtle.generateKey(
            {
                name: 'ECDSA',
                namedCurve: 'P-256'
            },
            true,
            ['sign', 'verify']
        );
    },

    async signChallenge(nonce, userId) {
        if (!this.signingKeyPair) {
            throw new Error('No signing key available');
        }
        return await this.signChallengeWithKeyPair(this.signingKeyPair, nonce, userId);
    },

    async signChallengeWithPending(nonce, userId) {
        if (!this.pendingSigningKeyPair) {
            throw new Error('No pending signing key available');
        }
        return await this.signChallengeWithKeyPair(this.pendingSigningKeyPair, nonce, userId);
    },

    async signChallengeWithKeyPair(signingKeyPair, nonce, userId) {
        if (!signingKeyPair || !signingKeyPair.privateKey) {
            throw new Error('No signing key available');
        }

        const message = nonce + ':' + userId;
        const encoded = new TextEncoder().encode(message);

        const signature = await window.crypto.subtle.sign(
            {
                name: 'ECDSA',
                hash: { name: 'SHA-256' }
            },
            signingKeyPair.privateKey,
            encoded
        );

        return new Uint8Array(signature);
    },

    async exportPublicKey() {
        return await this.exportPublicKeyFrom(this.keyPair);
    },

    async exportSigningPublicKey() {
        return await this.exportSigningPublicKeyFrom(this.signingKeyPair);
    },

    async exportPublicKeyFrom(keyPair) {
        if (!keyPair) return null;
        const exported = await window.crypto.subtle.exportKey('spki', keyPair.publicKey);
        return new Uint8Array(exported);
    },

    async exportSigningPublicKeyFrom(signingKeyPair) {
        if (!signingKeyPair) return null;
        const exported = await window.crypto.subtle.exportKey('spki', signingKeyPair.publicKey);
        return new Uint8Array(exported);
    },

    async importPublicKey(keyData) {
        if (typeof keyData === 'string') {
            keyData = this.base64ToBytes(keyData);
        } else if (Array.isArray(keyData)) {
            keyData = new Uint8Array(keyData);
        }
        return await window.crypto.subtle.importKey(
            'spki',
            keyData,
            {
                name: 'ECDH',
                namedCurve: 'P-256'
            },
            false,
            []
        );
    },

    async deriveSharedKey(otherPublicKeyData) {
        const otherPublicKey = await this.importPublicKey(otherPublicKeyData);
        return await window.crypto.subtle.deriveKey(
            {
                name: 'ECDH',
                public: otherPublicKey
            },
            this.keyPair.privateKey,
            {
                name: 'AES-GCM',
                length: 256
            },
            false,
            ['encrypt', 'decrypt']
        );
    },

    async exportKey(key) {
        const exported = await window.crypto.subtle.exportKey('raw', key);
        return new Uint8Array(exported);
    },

    async importKey(keyData) {
        return await window.crypto.subtle.importKey(
            'raw',
            keyData,
            {
                name: 'AES-GCM',
                length: 256
            },
            false,
            ['encrypt', 'decrypt']
        );
    },

    async encryptWithKey(key, plaintext) {
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encoded = new TextEncoder().encode(plaintext);
        const ciphertext = await window.crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            key,
            encoded
        );
        return {
            iv: Array.from(iv),
            ciphertext: Array.from(new Uint8Array(ciphertext))
        };
    },

    async decryptWithKey(key, encrypted) {
        const iv = new Uint8Array(encrypted.iv);
        const ciphertext = new Uint8Array(encrypted.ciphertext);
        const decrypted = await window.crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            key,
            ciphertext
        );
        return new TextDecoder().decode(decrypted);
    },

    async encryptRatchetStateForUser(ratchetState, userPublicKeyData) {
        const sharedKey = await this.deriveSharedKey(userPublicKeyData);
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encoded = new TextEncoder().encode(JSON.stringify(ratchetState));
        const encrypted = await window.crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            sharedKey,
            encoded
        );
        return {
            iv: this.bytesToBase64(iv),
            ciphertext: this.bytesToBase64(new Uint8Array(encrypted))
        };
    },

    async decryptRatchetState(encryptedState, senderPublicKeyData) {
        const sharedKey = await this.deriveSharedKey(senderPublicKeyData);
        const iv = this.base64ToBytes(encryptedState.iv);
        const ciphertext = this.base64ToBytes(encryptedState.ciphertext);
        const decrypted = await window.crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            sharedKey,
            ciphertext
        );
        return JSON.parse(new TextDecoder().decode(decrypted));
    },

    async initRoomRatchet(roomId) {
        const ratchet = new RoomRatchet(roomId);
        await ratchet.init();
        this.roomRatchets[roomId] = ratchet;
        return ratchet;
    },

    getRoomRatchet(roomId) {
        return this.roomRatchets[roomId];
    },

    async applyRatchetState(roomId, state) {
        let ratchet = this.roomRatchets[roomId];
        if (!ratchet) {
            ratchet = new RoomRatchet(roomId);
            this.roomRatchets[roomId] = ratchet;
        }
        await ratchet.setState(state);
    },

    async rekeyRoomRatchet(roomId) {
        let ratchet = this.roomRatchets[roomId];
        if (!ratchet) {
            ratchet = new RoomRatchet(roomId);
            this.roomRatchets[roomId] = ratchet;
        }
        await ratchet.init();
    },

    async encryptMessage(roomId, plaintext) {
        const ratchet = this.roomRatchets[roomId];
        if (!ratchet) {
            throw new Error('No room ratchet available');
        }
        const { key, messageNum, generation } = await ratchet.nextMessageKey();
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encoded = new TextEncoder().encode(plaintext);
        const aad = new TextEncoder().encode(JSON.stringify({
            room_id: roomId,
            generation: generation,
            message_num: messageNum
        }));
        const ciphertext = await window.crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv,
                additionalData: aad
            },
            key,
            encoded
        );
        return {
            iv: this.bytesToBase64(iv),
            ciphertext: this.bytesToBase64(new Uint8Array(ciphertext)),
            generation: generation,
            message_num: messageNum
        };
    },

    async decryptMessage(roomId, generation, messageNum, encrypted) {
        const ratchet = this.roomRatchets[roomId];
        if (!ratchet) {
            throw new Error('No room ratchet available');
        }
        const iv = this.base64ToBytes(encrypted.iv);
        const ciphertext = this.base64ToBytes(encrypted.ciphertext);
        return await ratchet.decryptMessage(generation, messageNum, iv, ciphertext);
    },

    getRatchetState(roomId) {
        const ratchet = this.roomRatchets[roomId];
        if (!ratchet) return null;
        return ratchet.getState();
    },

    getMessageInfo(roomId) {
        const ratchet = this.roomRatchets[roomId];
        if (!ratchet) return { generation: 0, messageNum: 0 };
        return {
            generation: ratchet.generation,
            messageNum: ratchet.messageNum
        };
    },

    async deriveKeyFromPassword(password, salt, iterations = this.PBKDF2_ITERATIONS) {
        const encoder = new TextEncoder();
        const keyMaterial = await window.crypto.subtle.importKey(
            'raw',
            encoder.encode(password),
            'PBKDF2',
            false,
            ['deriveKey']
        );

        return await window.crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: iterations,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    },

    async buildKeyBundle(keyPair, signingKeyPair) {
        if (!keyPair || !keyPair.privateKey || !keyPair.publicKey) {
            throw new Error('Invalid key pair');
        }
        if (!signingKeyPair || !signingKeyPair.privateKey || !signingKeyPair.publicKey) {
            throw new Error('Invalid signing key pair');
        }

        const privateKeyJwk = await window.crypto.subtle.exportKey('jwk', keyPair.privateKey);
        const publicKeySpki = await window.crypto.subtle.exportKey('spki', keyPair.publicKey);
        const signingPrivateKeyJwk = await window.crypto.subtle.exportKey('jwk', signingKeyPair.privateKey);
        const signingPublicKeySpki = await window.crypto.subtle.exportKey('spki', signingKeyPair.publicKey);

        return {
            privateKey: privateKeyJwk,
            publicKey: Array.from(new Uint8Array(publicKeySpki)),
            signingPrivateKey: signingPrivateKeyJwk,
            signingPublicKey: Array.from(new Uint8Array(signingPublicKeySpki))
        };
    },

    normalizeStoredKeyData(rawKeyData) {
        if (!rawKeyData || typeof rawKeyData !== 'object') {
            throw new Error('Invalid key data');
        }

        if (rawKeyData.active) {
            return {
                active: rawKeyData.active,
                pendingRotation: rawKeyData.pendingRotation || null
            };
        }

        // Backward compatibility with legacy format (v2-v4)
        return {
            active: rawKeyData,
            pendingRotation: null
        };
    },

    async importKeyBundle(bundle) {
        const privateKey = await window.crypto.subtle.importKey(
            'jwk',
            bundle.privateKey,
            { name: 'ECDH', namedCurve: 'P-256' },
            true,
            ['deriveKey', 'deriveBits']
        );

        const publicKey = await window.crypto.subtle.importKey(
            'spki',
            new Uint8Array(bundle.publicKey),
            { name: 'ECDH', namedCurve: 'P-256' },
            true,
            []
        );

        const signingPrivateKey = await window.crypto.subtle.importKey(
            'jwk',
            bundle.signingPrivateKey,
            { name: 'ECDSA', namedCurve: 'P-256' },
            true,
            ['sign']
        );

        const signingPublicKey = await window.crypto.subtle.importKey(
            'spki',
            new Uint8Array(bundle.signingPublicKey),
            { name: 'ECDSA', namedCurve: 'P-256' },
            true,
            ['verify']
        );

        return {
            keyPair: {
                privateKey: privateKey,
                publicKey: publicKey
            },
            signingKeyPair: {
                privateKey: signingPrivateKey,
                publicKey: signingPublicKey
            }
        };
    },

    async encryptAndStoreKeyData(password, keyData) {
        const salt = window.crypto.getRandomValues(new Uint8Array(16));
        const encryptionKey = await this.deriveKeyFromPassword(password, salt, this.PBKDF2_ITERATIONS);
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encoded = new TextEncoder().encode(JSON.stringify(keyData));
        const encrypted = await window.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            encryptionKey,
            encoded
        );

        const storedData = {
            salt: Array.from(salt),
            iv: Array.from(iv),
            data: Array.from(new Uint8Array(encrypted)),
            iterations: this.PBKDF2_ITERATIONS,
            version: 5
        };

        await KeyStore.set(this.STORAGE_KEY, storedData);
    },

    async decryptStoredKeyData(storedData, password) {
        if (storedData.version < 2) {
            throw new Error('Unsupported key storage version. Please create a new account.');
        }

        const salt = new Uint8Array(storedData.salt);
        const iv = new Uint8Array(storedData.iv);
        const encrypted = new Uint8Array(storedData.data);
        const storedIterations = Number(storedData.iterations);
        const iterations = Number.isInteger(storedIterations) && storedIterations >= this.LEGACY_PBKDF2_ITERATIONS
            ? storedIterations
            : this.LEGACY_PBKDF2_ITERATIONS;

        const encryptionKey = await this.deriveKeyFromPassword(password, salt, iterations);
        const decrypted = await window.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv },
            encryptionKey,
            encrypted
        );
        return this.normalizeStoredKeyData(JSON.parse(new TextDecoder().decode(decrypted)));
    },

    async saveKeyPair(password) {
        if (!this.keyPair) {
            throw new Error('No key pair to save');
        }
        if (!this.signingKeyPair) {
            throw new Error('No signing key pair to save');
        }

        const active = await this.buildKeyBundle(this.keyPair, this.signingKeyPair);
        await this.encryptAndStoreKeyData(password, {
            active: active,
            pendingRotation: null
        });
        this.pendingKeyPair = null;
        this.pendingSigningKeyPair = null;
    },

    async stagePendingRotation(password, nextKeyPair, nextSigningKeyPair) {
        if (!this.keyPair || !this.signingKeyPair) {
            throw new Error('Current keys must be loaded before rotation');
        }

        const active = await this.buildKeyBundle(this.keyPair, this.signingKeyPair);
        const pendingRotation = await this.buildKeyBundle(nextKeyPair, nextSigningKeyPair);
        await this.encryptAndStoreKeyData(password, {
            active: active,
            pendingRotation: pendingRotation
        });

        this.pendingKeyPair = nextKeyPair;
        this.pendingSigningKeyPair = nextSigningKeyPair;
    },

    async clearPendingRotation(password) {
        if (!this.keyPair || !this.signingKeyPair) {
            throw new Error('Current keys must be loaded before clearing pending rotation');
        }

        const active = await this.buildKeyBundle(this.keyPair, this.signingKeyPair);
        await this.encryptAndStoreKeyData(password, {
            active: active,
            pendingRotation: null
        });
        this.pendingKeyPair = null;
        this.pendingSigningKeyPair = null;
    },

    async promotePendingRotation(password) {
        if (!this.pendingKeyPair || !this.pendingSigningKeyPair) {
            throw new Error('No pending rotation keys available');
        }

        this.keyPair = this.pendingKeyPair;
        this.signingKeyPair = this.pendingSigningKeyPair;
        this.pendingKeyPair = null;
        this.pendingSigningKeyPair = null;

        await this.saveKeyPair(password);
    },

    hasPendingRotation() {
        return !!(this.pendingKeyPair && this.pendingSigningKeyPair);
    },

    async loadKeyPair(password) {
        const stored = await KeyStore.get(this.STORAGE_KEY);
        if (!stored) {
            return false;
        }

        try {
            const keyData = await this.decryptStoredKeyData(stored, password);
            const active = await this.importKeyBundle(keyData.active);

            this.keyPair = active.keyPair;
            this.signingKeyPair = active.signingKeyPair;
            this.pendingKeyPair = null;
            this.pendingSigningKeyPair = null;

            if (keyData.pendingRotation) {
                const pending = await this.importKeyBundle(keyData.pendingRotation);
                this.pendingKeyPair = pending.keyPair;
                this.pendingSigningKeyPair = pending.signingKeyPair;
            }

            return true;
        } catch (error) {
            console.error('Failed to load key pair:', error);
            return false;
        }
    },

    async hasStoredKeyPair() {
        try {
            const stored = await KeyStore.get(this.STORAGE_KEY);
            return !!stored;
        } catch {
            return false;
        }
    },

    async deleteStoredKeyPair() {
        await KeyStore.delete(this.STORAGE_KEY);
        this.keyPair = null;
        this.signingKeyPair = null;
        this.pendingKeyPair = null;
        this.pendingSigningKeyPair = null;
        this.roomRatchets = {};
    },

    clearRoomRatchets() {
        this.roomRatchets = {};
    },

    clearRuntimeState() {
        this.keyPair = null;
        this.signingKeyPair = null;
        this.pendingKeyPair = null;
        this.pendingSigningKeyPair = null;
        this.roomRatchets = {};
    },

    async signMessage(roomId, encryptedContent) {
        if (!this.signingKeyPair || !this.signingKeyPair.privateKey) {
            throw new Error('No signing key available');
        }

        const timestamp = Date.now();
        const ratchet = this.roomRatchets[roomId];
        const generation = Number.isInteger(encryptedContent.generation)
            ? encryptedContent.generation
            : (ratchet ? ratchet.generation : 0);
        const messageNum = Number.isInteger(encryptedContent.message_num)
            ? encryptedContent.message_num
            : (ratchet ? ratchet.messageNum : 0);

        const payload = JSON.stringify({
            room_id: roomId,
            iv: encryptedContent.iv,
            ciphertext: encryptedContent.ciphertext,
            timestamp: timestamp,
            generation: generation,
            message_num: messageNum
        });

        const encoded = new TextEncoder().encode(payload);
        const signature = await window.crypto.subtle.sign(
            {
                name: 'ECDSA',
                hash: { name: 'SHA-256' }
            },
            this.signingKeyPair.privateKey,
            encoded
        );

        return {
            signature: this.bytesToBase64(new Uint8Array(signature)),
            timestamp: timestamp,
            generation: generation,
            messageNum: messageNum
        };
    },

    getSigningPublicKey() {
        return this.signingKeyPair ? this.signingKeyPair.publicKey : null;
    },

    async importSigningPublicKey(keyData) {
        if (typeof keyData === 'string') {
            keyData = this.base64ToBytes(keyData);
        } else if (Array.isArray(keyData)) {
            keyData = new Uint8Array(keyData);
        }
        return await window.crypto.subtle.importKey(
            'spki',
            keyData,
            {
                name: 'ECDSA',
                namedCurve: 'P-256'
            },
            false,
            ['verify']
        );
    },

    async verifyMessageSignature(senderPublicKeyData, roomId, encryptedContent, timestamp, generation, messageNum, signature) {
        try {
            const publicKey = await this.importSigningPublicKey(senderPublicKeyData);
            
            const payload = JSON.stringify({
                room_id: roomId,
                iv: encryptedContent.iv,
                ciphertext: encryptedContent.ciphertext,
                timestamp: timestamp,
                generation: generation,
                message_num: messageNum
            });

            const encoded = new TextEncoder().encode(payload);
            const sigBytes = this.base64ToBytes(signature);

            return await window.crypto.subtle.verify(
                {
                    name: 'ECDSA',
                    hash: { name: 'SHA-256' }
                },
                publicKey,
                sigBytes,
                encoded
            );
        } catch (error) {
            console.error('Signature verification failed:', error);
            return false;
        }
    },

    async signRatchetStateTransfer(roomId, targetUserId, encryptedState, epoch, reason = '') {
        if (!this.signingKeyPair || !this.signingKeyPair.privateKey) {
            throw new Error('No signing key available');
        }

        const timestamp = Date.now();
        const payload = JSON.stringify({
            room_id: roomId,
            user_id: targetUserId,
            state: encryptedState,
            epoch: epoch,
            reason: reason || '',
            timestamp: timestamp
        });

        const encoded = new TextEncoder().encode(payload);
        const signature = await window.crypto.subtle.sign(
            {
                name: 'ECDSA',
                hash: { name: 'SHA-256' }
            },
            this.signingKeyPair.privateKey,
            encoded
        );

        return {
            timestamp: timestamp,
            signature: this.bytesToBase64(new Uint8Array(signature))
        };
    },

    async verifyRatchetStateTransferSignature(senderPublicKeyData, roomId, targetUserId, encryptedState, epoch, reason, timestamp, signature) {
        try {
            const publicKey = await this.importSigningPublicKey(senderPublicKeyData);
            const payload = JSON.stringify({
                room_id: roomId,
                user_id: targetUserId,
                state: encryptedState,
                epoch: epoch,
                reason: reason || '',
                timestamp: timestamp
            });
            const encoded = new TextEncoder().encode(payload);
            const sigBytes = this.base64ToBytes(signature);

            return await window.crypto.subtle.verify(
                {
                    name: 'ECDSA',
                    hash: { name: 'SHA-256' }
                },
                publicKey,
                sigBytes,
                encoded
            );
        } catch (error) {
            console.error('Ratchet state signature verification failed:', error);
            return false;
        }
    }
};
