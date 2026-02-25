const WS = {
    socket: null,
    handlers: {},
    reconnectAttempts: 0,
    maxReconnectAttempts: 5,

    connect() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        this.socket = new WebSocket(`${protocol}//${window.location.host}/ws`);

        this.socket.onopen = () => {
            console.log('WebSocket connected');
            this.reconnectAttempts = 0;
            this.emit('connected');
        };

        this.socket.onmessage = (event) => {
            const payloads = typeof event.data === 'string'
                ? event.data.split('\n')
                : [event.data];

            for (const payload of payloads) {
                if (typeof payload !== 'string' || payload.trim() === '') {
                    continue;
                }
                try {
                    const data = JSON.parse(payload);
                    this.emit('message', data);
                } catch (e) {
                    console.error('Failed to parse message:', e);
                }
            }
        };

        this.socket.onclose = () => {
            console.log('WebSocket disconnected');
            this.emit('disconnected');
            this.attemptReconnect();
        };

        this.socket.onerror = (error) => {
            console.error('WebSocket error:', error);
            this.emit('error', error);
        };
    },

    attemptReconnect() {
        if (this.reconnectAttempts < this.maxReconnectAttempts) {
            this.reconnectAttempts++;
            const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts), 30000);
            console.log(`Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts})`);
            setTimeout(() => this.connect(), delay);
        } else {
            this.emit('reconnect_failed');
        }
    },

    send(data) {
        if (this.socket && this.socket.readyState === WebSocket.OPEN) {
            this.socket.send(JSON.stringify(data));
            return true;
        } else {
            console.error('WebSocket not connected');
            return false;
        }
    },

    joinRoom(roomId, inviteCode = null) {
        const payload = {
            type: 'join',
            room_id: roomId
        };
        if (inviteCode) {
            payload.content = { invite_code: inviteCode };
        }
        return this.send(payload);
    },

    leaveRoom(roomId) {
        return this.send({
            type: 'leave',
            room_id: roomId
        });
    },

    async sendMessage(roomId, encryptedContent, signature, timestamp, generation, messageNum) {
        return this.send({
            type: 'message',
            room_id: roomId,
            content: encryptedContent,
            signature: signature,
            timestamp: timestamp,
            generation: generation,
            message_num: messageNum
        });
    },

    sendRoomKey(roomId, userId, encryptedKey) {
        this.send({
            type: 'room_key',
            room_id: roomId,
            content: {
                user_id: userId,
                key: encryptedKey
            }
        });
    },

    sendKeyRequest(roomId) {
        this.send({
            type: 'key_request',
            room_id: roomId
        });
    },

    sendRatchetState(roomId, userId, encryptedState, metadata = {}) {
        this.send({
            type: 'ratchet_state',
            room_id: roomId,
            content: {
                user_id: userId,
                state: encryptedState,
                epoch: Number.isInteger(metadata.epoch) ? metadata.epoch : 0,
                reason: metadata.reason || '',
                timestamp: Number.isInteger(metadata.timestamp) ? metadata.timestamp : 0,
                signature: typeof metadata.signature === 'string' ? metadata.signature : ''
            }
        });
    },

    on(event, handler) {
        if (!this.handlers[event]) {
            this.handlers[event] = [];
        }
        this.handlers[event].push(handler);
    },

    off(event, handler) {
        if (this.handlers[event]) {
            this.handlers[event] = this.handlers[event].filter(h => h !== handler);
        }
    },

    emit(event, data) {
        if (this.handlers[event]) {
            this.handlers[event].forEach(handler => handler(data));
        }
    },

    isConnected() {
        return this.socket && this.socket.readyState === WebSocket.OPEN;
    },

    manualReconnect() {
        this.reconnectAttempts = 0;
        this.connect();
    },

    disconnect() {
        if (this.socket) {
            this.socket.close();
            this.socket = null;
        }
        this.reconnectAttempts = this.maxReconnectAttempts;
    }
};
