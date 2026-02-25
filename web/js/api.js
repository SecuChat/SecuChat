const API = {
    baseURL: '/api',
    csrfToken: null,

    getCSRFCookie() {
        const cookies = document.cookie.split(';');
        for (const cookie of cookies) {
            const trimmed = cookie.trim();
            const separatorIndex = trimmed.indexOf('=');
            if (separatorIndex === -1) continue;

            const name = trimmed.slice(0, separatorIndex);
            const value = trimmed.slice(separatorIndex + 1);
            if (name === 'csrf_token') {
                return value;
            }
        }
        return null;
    },

    updateCSRFTokenFromResponse(response) {
        if (response) {
            const headerToken = response.headers.get('X-CSRF-Token');
            if (headerToken) {
                this.csrfToken = headerToken;
                return;
            }
        }

        const cookieToken = this.getCSRFCookie();
        if (cookieToken) {
            this.csrfToken = cookieToken;
        }
    },

    async fetchCSRFToken() {
        try {
            const response = await fetch(`${this.baseURL}/auth/me`, {
                method: 'GET',
                credentials: 'include'
            });
            this.updateCSRFTokenFromResponse(response);
            return this.csrfToken;
        } catch (e) {
            this.updateCSRFTokenFromResponse(null);
            return this.csrfToken;
        }
    },

    async request(method, endpoint, body = null, requireCSRF = true) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 15000);

        const options = {
            method,
            headers: {
                'Content-Type': 'application/json'
            },
            credentials: 'include',
            signal: controller.signal
        };

        if (requireCSRF && (method === 'POST' || method === 'PUT' || method === 'DELETE')) {
            if (!this.csrfToken) {
                this.csrfToken = this.getCSRFCookie();
            }
            if (!this.csrfToken) {
                await this.fetchCSRFToken();
            }
            if (this.csrfToken) {
                options.headers['X-CSRF-Token'] = this.csrfToken;
            }
        }

        if (body) {
            options.body = JSON.stringify(body);
        }

        try {
            const response = await fetch(`${this.baseURL}${endpoint}`, options);
            clearTimeout(timeoutId);
            this.updateCSRFTokenFromResponse(response);

            if (!response.ok) {
                let errorMessage = `HTTP ${response.status}`;
                let errorCode = 'UNKNOWN_ERROR';
                try {
                    const errorData = await response.json();
                    errorMessage = errorData.error || errorMessage;
                    errorCode = errorData.code || errorCode;
                } catch (e) {
                    errorMessage = await response.text() || errorMessage;
                }
                const error = new Error(errorMessage);
                error.code = errorCode;
                error.status = response.status;
                throw error;
            }

            if (response.status === 204) return null;

            return await response.json();
        } catch (err) {
            clearTimeout(timeoutId);
            if (err.name === 'AbortError') {
                const error = new Error('Request timed out');
                error.code = 'TIMEOUT';
                error.status = 0;
                throw error;
            }
            throw err;
        }
    },

    async createAccount(username, password, publicKey, signingKey) {
        return await this.request('POST', '/auth/create', {
            username,
            password,
            public_key: Crypto.bytesToBase64(publicKey),
            signing_key: Crypto.bytesToBase64(signingKey)
        });
    },

    async login(username, password) {
        return await this.request('POST', '/auth/login', {
            username,
            password
        });
    },

    async verifyLogin(username, nonce, signature) {
        return await this.request('POST', '/auth/verify', {
            username,
            nonce,
            signature: Crypto.bytesToBase64(signature)
        });
    },

    async getMe() {
        try {
            return await this.request('GET', '/auth/me', null, false);
        } catch {
            return null;
        }
    },

    async logout() {
        return await this.request('POST', '/auth/logout');
    },

    async getUserKey(userId, roomId = null) {
        const roomQuery = roomId ? `?room_id=${encodeURIComponent(roomId)}` : '';
        return await this.request('GET', `/users/${userId}/key${roomQuery}`);
    },

    async getRooms() {
        return await this.request('GET', '/rooms');
    },

    async createRoom(name, isPrivate = false) {
        return await this.request('POST', '/rooms', { name, is_private: isPrivate });
    },

    async getRoom(roomId) {
        return await this.request('GET', `/rooms/${roomId}`);
    },

    async joinRoom(roomId, inviteCode = null) {
        const body = inviteCode ? { invite_code: inviteCode } : {};
        return await this.request('POST', `/rooms/${roomId}/join`, Object.keys(body).length > 0 ? body : null);
    },

    async joinRoomByCode(inviteCode) {
        return await this.request('POST', '/rooms/join-by-code', { invite_code: inviteCode });
    },

    async leaveRoom(roomId) {
        return await this.request('POST', `/rooms/${roomId}/leave`);
    },

    async getRoomMembers(roomId) {
        return await this.request('GET', `/rooms/${roomId}/members`);
    },

    async regenerateInviteCode(roomId) {
        return await this.request('POST', `/rooms/${roomId}/regenerate-code`);
    },

    async deleteAccount(password, confirmation) {
        return await this.request('POST', '/auth/delete-account', { password, confirmation });
    },

    async confirmDeleteAccount(nonce, signature) {
        return await this.request('POST', '/auth/confirm-delete', {
            nonce,
            signature: Crypto.bytesToBase64(signature)
        });
    },

    async rotateKeys(password) {
        return await this.request('POST', '/auth/rotate-keys', { password });
    },

    async confirmRotateKeys(nonce, signature, newPublicKey, newSigningKey) {
        return await this.request('POST', '/auth/confirm-rotate-keys', {
            nonce,
            signature: Crypto.bytesToBase64(signature),
            new_public_key: Crypto.bytesToBase64(newPublicKey),
            new_signing_key: Crypto.bytesToBase64(newSigningKey)
        });
    }
};
