const App = {
    currentUser: null,
    currentRoom: null,
    rooms: [],
    members: {},
    publicKeyCache: {},
    signingKeyCache: {},
    pendingAuthMode: null,
    pendingUsername: null,
    pendingPassword: null,
    pendingChallenge: null,
    keyMasterRooms: {},
    pendingKeyRequests: {},
    ratchetRecoveryAcknowledged: {},
    roomReady: false,
    privateRoomCodes: {},
    memberSnapshots: {},
    roomEpochs: {},
    keyPassword: null,
    pendingRotationContext: null,
    seenMessages: new Set(),
    MAX_SEEN_MESSAGES: 500,

    KEY_REQUEST_TIMEOUT: 5000,
    MAX_KEY_RETRIES: 3,

    async init() {
        await Crypto.init();
        this.bindEvents();
        await this.checkAuth();
    },

    bindEvents() {
        document.getElementById('create-btn').addEventListener('click', () => this.handleAuth('create'));
        document.getElementById('login-btn').addEventListener('click', () => this.handleAuth('login'));
        document.getElementById('logout-btn').addEventListener('click', () => this.logout());
        document.getElementById('create-room-btn').addEventListener('click', () => this.showCreateRoomModal());
        document.getElementById('refresh-rooms-btn').addEventListener('click', () => this.loadRooms());
        document.getElementById('confirm-create-room').addEventListener('click', () => this.createRoom());
        document.getElementById('cancel-create-room').addEventListener('click', () => this.hideCreateRoomModal());
        document.getElementById('leave-room-btn').addEventListener('click', () => this.leaveRoom());
        document.getElementById('send-btn').addEventListener('click', () => this.sendMessage());
        document.getElementById('message-input').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.sendMessage();
        });
        document.getElementById('username').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') document.getElementById('password').focus();
        });
        document.getElementById('password').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.handleAuth(this.pendingAuthMode || 'create');
        });
        document.getElementById('room-name-input').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.createRoom();
        });
        document.getElementById('password-input').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.handlePasswordConfirm();
        });
        document.getElementById('confirm-password-input').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.handlePasswordConfirm();
        });
        document.getElementById('confirm-password-btn').addEventListener('click', () => this.handlePasswordConfirm());
        document.getElementById('cancel-password-btn').addEventListener('click', () => this.handlePasswordCancel());
        document.getElementById('copy-invite-code-btn').addEventListener('click', () => this.copyInviteCode());
        document.getElementById('regenerate-code-btn').addEventListener('click', () => this.regenerateInviteCode());
        document.getElementById('join-by-code-btn').addEventListener('click', () => this.showJoinByCodeModal());
        document.getElementById('confirm-join-code').addEventListener('click', () => this.joinByCode());
        document.getElementById('cancel-join-code').addEventListener('click', () => this.hideJoinByCodeModal());
        document.getElementById('invite-code-input').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.joinByCode();
        });
        document.getElementById('settings-btn').addEventListener('click', () => this.showAccountSettings());
        document.getElementById('close-settings-btn').addEventListener('click', () => this.hideAccountSettings());
        document.getElementById('delete-account-btn').addEventListener('click', () => this.deleteAccount());
        document.getElementById('rotate-keys-btn').addEventListener('click', () => this.rotateKeys());

        WS.on('message', (data) => this.handleWSMessage(data));
        WS.on('disconnected', () => this.handleWSDisconnected());
        WS.on('connected', () => this.handleWSConnected());
        WS.on('reconnect_failed', () => this.handleWSReconnectFailed());
    },

    showInputModal(title, label, placeholder, inputType = 'text') {
        return new Promise((resolve) => {
            const modal = document.getElementById('input-modal');
            const field = document.getElementById('input-modal-field');
            document.getElementById('input-modal-title').textContent = title;
            document.getElementById('input-modal-label').textContent = label;
            field.placeholder = placeholder || '';
            field.type = inputType;
            field.value = '';
            modal.classList.remove('hidden');
            field.focus();

            const cleanup = () => {
                modal.classList.add('hidden');
                confirmBtn.removeEventListener('click', onConfirm);
                cancelBtn.removeEventListener('click', onCancel);
                field.removeEventListener('keypress', onKeypress);
            };
            const onConfirm = () => { cleanup(); resolve(field.value || null); };
            const onCancel = () => { cleanup(); resolve(null); };
            const onKeypress = (e) => { if (e.key === 'Enter') onConfirm(); };

            const confirmBtn = document.getElementById('confirm-input-modal');
            const cancelBtn = document.getElementById('cancel-input-modal');
            confirmBtn.addEventListener('click', onConfirm);
            cancelBtn.addEventListener('click', onCancel);
            field.addEventListener('keypress', onKeypress);
        });
    },

    async checkAuth() {
        const user = await API.getMe();
        if (user) {
            if (await Crypto.hasStoredKeyPair()) {
                this.currentUser = user;
                this.pendingAuthMode = 'session';
                this.showPasswordModal('unlock');
            } else {
                await API.logout();
                this.showError('Session expired. Please log in again.');
            }
        }
        await API.fetchCSRFToken();
    },

    async handleAuth(mode) {
        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value;
        
        if (!username) {
            this.showError('Please enter a username');
            return;
        }

        if (username.length < 3 || username.length > 32) {
            this.showError('Username must be between 3 and 32 characters');
            return;
        }

        if (!/^[a-zA-Z0-9_]+$/.test(username)) {
            this.showError('Username can only contain letters, numbers, and underscores');
            return;
        }

        if (!password) {
            this.showError('Please enter a password');
            return;
        }

        if (password.length < 8) {
            this.showError('Password must be at least 8 characters');
            return;
        }

        this.pendingAuthMode = mode;
        this.pendingUsername = username;
        this.pendingPassword = password;

        let hasStoredKeys = false;
        try {
            hasStoredKeys = await Crypto.hasStoredKeyPair();
        } catch {
            hasStoredKeys = false;
        }

        if (mode === 'login') {
            if (hasStoredKeys) {
                this.showPasswordModal('unlock');
            } else {
                this.showError('No encryption keys found. You must use the same browser where you created your account, or create a new account.');
            }
        } else if (mode === 'create') {
            if (hasStoredKeys) {
                this.pendingAuthMode = null;
                this.pendingUsername = null;
                this.pendingPassword = null;
                this.showError('Encryption keys already exist in this browser. Use Login, or clear local browser data before creating a new account.');
            } else {
                this.showPasswordModal('set');
            }
        }
    },

    showPasswordModal(mode) {
        const modal = document.getElementById('password-modal');
        const title = document.getElementById('password-modal-title');
        const desc = document.getElementById('password-modal-desc');
        const confirmGroup = document.getElementById('confirm-password-group');
        const passwordInput = document.getElementById('password-input');
        const confirmPasswordInput = document.getElementById('confirm-password-input');
        const errorText = document.getElementById('password-error');

        modal.classList.remove('hidden');
        errorText.classList.add('hidden');
        passwordInput.value = '';
        confirmPasswordInput.value = '';

        if (mode === 'unlock') {
            title.textContent = 'Unlock Keys';
            desc.textContent = 'Enter your key password to decrypt your encryption keys.';
            confirmGroup.classList.add('hidden');
        } else if (mode === 'set') {
            if (this.pendingAuthMode === 'rotate') {
                title.textContent = 'Confirm Key Password';
                desc.textContent = 'Enter the key password to stage and safely finalize key rotation.';
            } else {
                title.textContent = 'Set Key Password';
                desc.textContent = 'Create a password to protect your encryption keys. You will need this password to access your account.';
            }
            confirmGroup.classList.remove('hidden');
        }

        modal.dataset.mode = mode;
        passwordInput.focus();
    },

    hidePasswordModal() {
        document.getElementById('password-modal').classList.add('hidden');
    },

    async handlePasswordConfirm() {
        const mode = document.getElementById('password-modal').dataset.mode;
        const password = document.getElementById('password-input').value;
        const confirmPassword = document.getElementById('confirm-password-input').value;
        const errorText = document.getElementById('password-error');

        if (!password) {
            this.showPasswordError('Please enter a password');
            return;
        }

        if (password.length < 8) {
            this.showPasswordError('Password must be at least 8 characters');
            return;
        }

        if (mode === 'set') {
            if (password !== confirmPassword) {
                this.showPasswordError('Passwords do not match');
                return;
            }
            if (this.pendingAuthMode === 'rotate') {
                await this.completeSafeKeyRotation(password);
                return;
            }
            await this.completeAuthWithNewKeys(password);
        } else if (mode === 'unlock') {
            await this.unlockWithPassword(password);
        }
    },

    handlePasswordCancel() {
        this.hidePasswordModal();
        if (this.pendingAuthMode === 'rotate') {
            this.pendingAuthMode = null;
            this.pendingRotationContext = null;
            this.showError('Key rotation canceled');
            return;
        }
        if (this.pendingAuthMode) {
            this.pendingAuthMode = null;
            this.pendingUsername = null;
            this.pendingPassword = null;
        }
        if (this.currentUser) {
            this.logout();
        }
    },

    showPasswordError(message) {
        const errorText = document.getElementById('password-error');
        errorText.textContent = message;
        errorText.classList.remove('hidden');
    },

    async unlockWithPassword(password) {
        const success = await Crypto.loadKeyPair(password);
        if (success) {
            this.keyPassword = password;
            this.hidePasswordModal();

            if (this.pendingAuthMode === 'login') {
                await this.completeLogin();
            } else if (this.pendingAuthMode === 'session') {
                this.keyPassword = null;
                this.pendingAuthMode = null;
                this.pendingUsername = null;
                this.pendingPassword = null;
                this.showChatScreen();
            } else {
                this.keyPassword = null;
                this.pendingAuthMode = null;
                this.pendingUsername = null;
                this.pendingPassword = null;
                if (this.currentUser) {
                    this.showChatScreen();
                }
            }
        } else {
            this.keyPassword = null;
            this.showPasswordError('Incorrect password. Please try again.');
        }
    },

    async completeLogin() {
        try {
            let challenge = await API.login(this.pendingUsername, this.pendingPassword);
            const challengeUserID = challenge.user_id || (this.currentUser && this.currentUser.id);
            if (!challengeUserID) {
                throw new Error('Invalid login challenge');
            }

            let user;
            let usedPendingRotationKeys = false;

            try {
                const signature = await Crypto.signChallenge(challenge.nonce, challengeUserID);
                user = await API.verifyLogin(this.pendingUsername, challenge.nonce, signature);
            } catch (error) {
                const shouldTryPending = error && error.code === 'INVALID_SIGNATURE' && Crypto.hasPendingRotation();
                if (!shouldTryPending) {
                    throw error;
                }

                challenge = await API.login(this.pendingUsername, this.pendingPassword);
                const pendingUserID = challenge.user_id || challengeUserID;
                const pendingSignature = await Crypto.signChallengeWithPending(challenge.nonce, pendingUserID);
                user = await API.verifyLogin(this.pendingUsername, challenge.nonce, pendingSignature);
                usedPendingRotationKeys = true;
            }

            this.currentUser = user;

            if (usedPendingRotationKeys) {
                if (!this.keyPassword) {
                    throw new Error('Missing key password for pending rotation recovery');
                }
                await Crypto.promotePendingRotation(this.keyPassword);
                this.keyPassword = null;
                this.showError('Recovered interrupted key rotation. New keys are now active.', true);
            } else if (Crypto.hasPendingRotation() && this.keyPassword) {
                // If login succeeded with active keys, pending rotation was not finalized server-side.
                try {
                    await Crypto.clearPendingRotation(this.keyPassword);
                } catch (cleanupError) {
                    console.error('Failed to clear stale pending rotation:', cleanupError);
                }
                this.keyPassword = null;
            } else {
                this.keyPassword = null;
            }
             
            this.pendingAuthMode = null;
            this.pendingUsername = null;
            this.pendingPassword = null;
            this.showChatScreen();
        } catch (error) {
            this.showError(error.message || 'Login failed');
            this.logout();
        }
    },

    async completeAuthWithNewKeys(keyPassword) {
        try {
            await Crypto.generateKeyPair();
            await Crypto.generateSigningKeyPair();
            const publicKey = await Crypto.exportPublicKey();
            const signingKey = await Crypto.exportSigningPublicKey();
            
            const user = await API.createAccount(this.pendingUsername, this.pendingPassword, publicKey, signingKey);
            this.currentUser = user;

            await Crypto.saveKeyPair(keyPassword);
            this.keyPassword = null;

            this.hidePasswordModal();
            this.pendingAuthMode = null;
            this.pendingUsername = null;
            this.pendingPassword = null;
            this.showChatScreen();
        } catch (error) {
            this.showPasswordError(error.message || 'Authentication failed');
        }
    },

    async completeSafeKeyRotation(keyPassword) {
        if (!this.pendingRotationContext) {
            this.showPasswordError('No key rotation request in progress');
            return;
        }

        try {
            await Crypto.stagePendingRotation(
                keyPassword,
                this.pendingRotationContext.newKeyPair,
                this.pendingRotationContext.newSigningKeyPair
            );

            const newPublicKey = await Crypto.exportPublicKeyFrom(this.pendingRotationContext.newKeyPair);
            const newSigningKey = await Crypto.exportSigningPublicKeyFrom(this.pendingRotationContext.newSigningKeyPair);

            await API.confirmRotateKeys(
                this.pendingRotationContext.challenge.nonce,
                this.pendingRotationContext.signature,
                newPublicKey,
                newSigningKey
            );

            await Crypto.promotePendingRotation(keyPassword);
            this.keyPassword = null;
            this.pendingRotationContext = null;
            this.pendingAuthMode = null;
            this.hidePasswordModal();
            this.showError('Keys rotated and saved successfully', true);
        } catch (error) {
            try {
                if (Crypto.hasPendingRotation()) {
                    await Crypto.clearPendingRotation(keyPassword);
                }
            } catch (cleanupError) {
                console.error('Failed to clean up pending rotation data:', cleanupError);
            }
            this.pendingRotationContext = null;
            this.pendingAuthMode = null;
            this.hidePasswordModal();
            this.showError(error.message || 'Key rotation failed before local commit could be finalized');
        }
    },

    async showChatScreen() {
        document.getElementById('auth-screen').classList.add('hidden');
        document.getElementById('chat-screen').classList.remove('hidden');
        document.getElementById('current-user').textContent = this.currentUser.username;

        WS.connect();
        await this.loadRooms();
    },

    handleWSDisconnected() {
        for (const req of Object.values(this.pendingKeyRequests)) {
            if (req && req.timer) {
                clearTimeout(req.timer);
            }
        }
        this.pendingKeyRequests = {};
        this.keyPassword = null;
        this.roomReady = false;
        this.showError('Connection lost. Reconnecting...');
    },

    handleWSReconnectFailed() {
        this.showReconnectPrompt();
    },

    showReconnectPrompt() {
        const existing = document.querySelector('.error-toast');
        if (existing) existing.remove();

        const toast = document.createElement('div');
        toast.className = 'error-toast';
        toast.style.cursor = 'pointer';
        toast.textContent = 'Connection lost. Tap to reconnect.';
        toast.addEventListener('click', () => {
            toast.remove();
            WS.manualReconnect();
        });
        document.body.appendChild(toast);
    },

    handleWSConnected() {
        this.showError('Connected!', true);

        if (!this.currentRoom) {
            return;
        }

        let inviteCode = null;
        if (this.currentRoom.is_private) {
            inviteCode = this.privateRoomCodes[this.currentRoom.id];
            if (!inviteCode) {
                this.roomReady = false;
                this.addSystemMessage('Reconnected. Enter invite code to rejoin private room.');
                return;
            }
        }

        this.roomReady = false;
        WS.joinRoom(this.currentRoom.id, inviteCode);
    },

    async loadRooms() {
        try {
            this.rooms = await API.getRooms();
            this.rooms.forEach(room => this.setRoomEpoch(room.id, room.current_epoch));
            this.renderRoomList();
        } catch (error) {
            this.showError('Failed to load rooms');
        }
    },

    renderRoomList() {
        const container = document.getElementById('room-list');
        container.innerHTML = '';

        this.rooms.forEach(room => {
            const div = document.createElement('div');
            div.className = 'room-item' + (this.currentRoom && this.currentRoom.id === room.id ? ' active' : '');
            const badge = room.is_private 
                ? '<span class="room-badge private">Private</span>'
                : '<span class="room-badge public">Public</span>';
            div.innerHTML = `
                <div class="room-name">${this.escapeHtml(room.name)} ${badge}</div>
            `;
            div.addEventListener('click', () => this.selectRoom(room));
            container.appendChild(div);
        });
    },

    async selectRoom(room) {
        if (room.is_private) {
            this.showInviteCodeInput(room);
            return;
        }

        await this.joinRoomInternal(room);
    },

    async showInviteCodeInput(room) {
        const code = await this.showInputModal('Private Room', 'Invite Code', 'Enter the invite code');
        if (code) {
            this.joinRoomWithCode(room, code);
        }
    },

    async joinRoomWithCode(room, code) {
        try {
            await this.joinRoomInternal(room, code);
        } catch (error) {
            this.showError(error.message || 'Invalid invite code');
        }
    },

    async joinRoomInternal(room, inviteCode = null) {
        if (room.is_private) {
            inviteCode = (inviteCode || '').trim();
            if (!inviteCode) {
                throw new Error('Invite code required for private room');
            }
        }

        if (this.currentRoom && this.currentRoom.id !== room.id) {
            WS.leaveRoom(this.currentRoom.id);
            if (this.currentRoom.is_private) {
                delete this.privateRoomCodes[this.currentRoom.id];
            }
            delete this.ratchetRecoveryAcknowledged[this.currentRoom.id];
            delete this.memberSnapshots[this.currentRoom.id];
            this.seenMessages.clear();
            this.roomReady = false;
        }

        this.currentRoom = room;
        document.getElementById('no-room-selected').classList.add('hidden');
        document.getElementById('room-view').classList.remove('hidden');
        document.getElementById('room-name').textContent = room.name;
        document.getElementById('messages').innerHTML = '';

        this.renderRoomList();

        try {
            const roomData = await API.joinRoom(room.id, room.is_private ? inviteCode : null);
            this.setRoomEpoch(room.id, roomData.current_epoch);
            if (room.is_private) {
                this.privateRoomCodes[room.id] = inviteCode;
            }
            this.members = {};
            (roomData.members || []).forEach(m => {
                this.members[m.id] = m;
                this.publicKeyCache[m.id] = Crypto.base64ToBytes(m.public_key);
                if (m.signing_key) {
                    this.signingKeyCache[m.id] = Crypto.base64ToBytes(m.signing_key);
                }
            });
            this.memberSnapshots[room.id] = Object.keys(this.members).sort();
            this.keyMasterRooms[room.id] = this.isCurrentRoomLeader(room.id);

            const fullRoom = await API.getRoom(room.id);
            this.currentRoom = { ...room, ...fullRoom };
            this.setRoomEpoch(room.id, this.currentRoom.current_epoch);

            if (this.currentRoom.is_private && this.currentRoom.invite_code) {
                document.getElementById('invite-code-section').classList.remove('hidden');
                document.getElementById('invite-code-display').textContent = this.currentRoom.invite_code;
            } else {
                document.getElementById('invite-code-section').classList.add('hidden');
            }

            this.roomReady = false;
            WS.joinRoom(room.id, room.is_private ? inviteCode : null);

            const existingMembers = Object.keys(this.members).filter(
                id => id !== this.currentUser.id
            );

            if (!Crypto.getRoomRatchet(room.id)) {
                if (existingMembers.length === 0) {
                    await this.alignRatchetToEpoch(room.id, this.getRoomEpoch(room.id));
                    this.keyMasterRooms[room.id] = true;
                    this.roomReady = true;
                    this.addSystemMessage('You are the first member. Room ratchet initialized.');
                } else {
                    void this.requestRatchetStateWithTimeout(room.id);
                }
            } else {
                const localGeneration = this.getLocalRatchetGeneration(room.id);
                const requiredEpoch = this.getRoomEpoch(room.id);
                if (localGeneration >= requiredEpoch) {
                    this.roomReady = true;
                } else {
                    this.roomReady = false;
                    if (this.keyMasterRooms[room.id]) {
                        await this.performMembershipRekey(room.id, 'epoch_sync');
                    } else if (!this.pendingKeyRequests[room.id]) {
                        void this.requestRatchetStateWithTimeout(room.id);
                    }
                }
            }

            this.updateMemberCount();
        } catch (error) {
            this.roomReady = false;
            if (room.is_private) {
                delete this.privateRoomCodes[room.id];
            }
            delete this.ratchetRecoveryAcknowledged[room.id];
            delete this.memberSnapshots[room.id];
            this.currentRoom = null;
            document.getElementById('no-room-selected').classList.remove('hidden');
            document.getElementById('room-view').classList.add('hidden');
            document.getElementById('invite-code-section').classList.add('hidden');
            this.renderRoomList();
            this.showError(error.message || 'Failed to join room');
        }
    },

    normalizeEpoch(epoch) {
        const parsed = Number(epoch);
        return Number.isInteger(parsed) && parsed > 0 ? parsed : 1;
    },

    setRoomEpoch(roomId, epoch) {
        if (!roomId) return 1;
        const normalized = this.normalizeEpoch(epoch);
        const previous = this.normalizeEpoch(this.roomEpochs[roomId]);
        const next = normalized > previous ? normalized : previous;
        this.roomEpochs[roomId] = next;
        if (this.currentRoom && this.currentRoom.id === roomId) {
            this.currentRoom.current_epoch = next;
        }
        return next;
    },

    getRoomEpoch(roomId) {
        if (!roomId) return 1;
        return this.normalizeEpoch(this.roomEpochs[roomId]);
    },

    getLocalRatchetGeneration(roomId) {
        const state = Crypto.getRatchetState(roomId);
        if (!state || !Number.isInteger(state.generation) || state.generation <= 0) {
            return 0;
        }
        return state.generation;
    },

    async alignRatchetToEpoch(roomId, targetEpoch) {
        const requiredEpoch = this.normalizeEpoch(targetEpoch);
        let state = Crypto.getRatchetState(roomId);
        if (!state) {
            await Crypto.initRoomRatchet(roomId);
            state = Crypto.getRatchetState(roomId);
        }

        let generation = this.getLocalRatchetGeneration(roomId);
        let safetyCounter = 0;
        while (generation < requiredEpoch && safetyCounter < 1024) {
            await Crypto.rekeyRoomRatchet(roomId);
            generation = this.getLocalRatchetGeneration(roomId);
            safetyCounter++;
        }

        if (generation < requiredEpoch) {
            throw new Error(`Failed to align room ratchet generation for ${roomId}`);
        }
        return generation;
    },

    getSortedMemberIDs() {
        return Object.keys(this.members).sort();
    },

    getRoomLeaderId(roomId) {
        if (!this.currentRoom || this.currentRoom.id !== roomId) {
            return null;
        }
        const members = this.getSortedMemberIDs();
        return members.length > 0 ? members[0] : null;
    },

    isCurrentRoomLeader(roomId) {
        return !!(this.currentUser && this.getRoomLeaderId(roomId) === this.currentUser.id);
    },

    async distributeRatchetState(roomId, reason = 'membership_change', targetUserId = null) {
        const targetIDs = targetUserId
            ? [targetUserId]
            : this.getSortedMemberIDs().filter(id => id !== this.currentUser.id);

        for (const memberID of targetIDs) {
            await this.sendRatchetStateToUser(roomId, memberID, reason);
        }
    },

    async performMembershipRekey(roomId, reason = 'membership_change') {
        if (!this.currentRoom || this.currentRoom.id !== roomId) {
            return;
        }

        try {
            await Crypto.rekeyRoomRatchet(roomId);
            await this.alignRatchetToEpoch(roomId, this.getRoomEpoch(roomId));
            await this.distributeRatchetState(roomId, reason);
            this.keyMasterRooms[roomId] = true;
            this.roomReady = this.getLocalRatchetGeneration(roomId) >= this.getRoomEpoch(roomId);
            const message = reason === 'epoch_sync'
                ? 'Security rekey completed to synchronize room epoch.'
                : 'Security rekey completed for room membership change.';
            this.addSystemMessage(message);
        } catch (error) {
            console.error('Failed to perform membership rekey:', error);
            this.roomReady = false;
        }
    },

    async requestRatchetStateWithTimeout(roomId) {
        if (!WS.isConnected()) {
            return;
        }

        if (!this.pendingKeyRequests[roomId]) {
            this.pendingKeyRequests[roomId] = { attempts: 0, timer: null };
        }
        
        const req = this.pendingKeyRequests[roomId];
        req.attempts++;
        
        if (req.attempts > this.MAX_KEY_RETRIES) {
            if (!this.currentRoom || this.currentRoom.id !== roomId) {
                delete this.pendingKeyRequests[roomId];
                return;
            }

            if (!this.ratchetRecoveryAcknowledged[roomId]) {
                const roomName = this.currentRoom?.name || 'this room';
                const confirmed = window.confirm(
                    `No active key holder responded for "${roomName}".\n\n` +
                    'Initialize a new room key now? Members still using an older key may need to rejoin before they can decrypt new messages.'
                );
                if (!confirmed) {
                    this.addSystemMessage('Room key initialization canceled. Leave and rejoin when another member is online, or retry later.');
                    delete this.pendingKeyRequests[roomId];
                    return;
                }
                this.ratchetRecoveryAcknowledged[roomId] = true;
            }

            try {
                if (Crypto.getRoomRatchet(roomId)) {
                    await Crypto.rekeyRoomRatchet(roomId);
                }
                await this.alignRatchetToEpoch(roomId, this.getRoomEpoch(roomId));
                this.keyMasterRooms[roomId] = true;
                await this.distributeRatchetState(roomId, 'recovery_rekey');
                if (this.currentRoom && this.currentRoom.id === roomId) {
                    this.roomReady = this.getLocalRatchetGeneration(roomId) >= this.getRoomEpoch(roomId);
                }
                this.addSystemMessage('No active key holder responded. Initialized and distributed a fresh room ratchet.');
            } catch (error) {
                console.error('Failed to initialize fallback room ratchet:', error);
                this.addSystemMessage('Failed to initialize room ratchet. Please try rejoining.');
            }
            delete this.pendingKeyRequests[roomId];
            return;
        }
        
        WS.sendKeyRequest(roomId);
        
        this.addSystemMessage(`Requesting room ratchet state (attempt ${req.attempts}/${this.MAX_KEY_RETRIES})...`);
        
        req.timer = setTimeout(() => {
            if (this.pendingKeyRequests[roomId]) {
                void this.requestRatchetStateWithTimeout(roomId);
            }
        }, this.KEY_REQUEST_TIMEOUT);
    },

    async leaveRoom() {
        if (!this.currentRoom) return;

        if (this.pendingKeyRequests[this.currentRoom.id]) {
            clearTimeout(this.pendingKeyRequests[this.currentRoom.id].timer);
            delete this.pendingKeyRequests[this.currentRoom.id];
        }

        WS.leaveRoom(this.currentRoom.id);
        await API.leaveRoom(this.currentRoom.id);
        if (this.currentRoom.is_private) {
            delete this.privateRoomCodes[this.currentRoom.id];
        }
        delete this.ratchetRecoveryAcknowledged[this.currentRoom.id];
        delete this.keyMasterRooms[this.currentRoom.id];
        delete this.memberSnapshots[this.currentRoom.id];
        
        this.currentRoom = null;
        this.members = {};
        this.roomReady = false;
        document.getElementById('no-room-selected').classList.remove('hidden');
        document.getElementById('room-view').classList.add('hidden');
        document.getElementById('invite-code-section').classList.add('hidden');
        this.renderRoomList();
    },

    async handleWSMessage(data) {
        switch (data.type) {
            case 'message':
                await this.handleChatMessage(data);
                break;
            case 'join':
                if (this.currentRoom && data.room_id === this.currentRoom.id) {
                    this.addSystemMessage(`${data.sender} joined the room`);
                }
                break;
            case 'leave':
                if (this.currentRoom && data.room_id === this.currentRoom.id) {
                    this.addSystemMessage(`${data.sender} left the room`);
                }
                break;
            case 'members':
                await this.updateMembersList(data.room_id, data.content, data.generation);
                break;
            case 'key_request':
                await this.handleKeyRequest(data);
                break;
            case 'ratchet_state':
                await this.handleRatchetState(data);
                break;
            case 'key_rotated':
                this.handleKeyRotated(data);
                break;
            case 'user_deleted':
                this.handleUserDeleted(data);
                break;
            case 'room_deleted':
                this.handleRoomDeleted(data);
                break;
        }
    },

    handleKeyRotated(data) {
        if (!data.content) return;
        const { user_id, username, public_key, signing_key } = data.content;
        if (!user_id) return;

        // Update caches with new keys
        delete this.publicKeyCache[user_id];
        delete this.signingKeyCache[user_id];
        if (public_key) {
            this.publicKeyCache[user_id] = Crypto.base64ToBytes(public_key);
        }
        if (signing_key) {
            this.signingKeyCache[user_id] = Crypto.base64ToBytes(signing_key);
        }
        if (this.members[user_id]) {
            if (public_key) this.members[user_id].public_key = public_key;
            if (signing_key) this.members[user_id].signing_key = signing_key;
        }

        this.addSystemMessage(`${username || user_id} rotated their encryption keys`);
    },

    handleUserDeleted(data) {
        const userId = data.sender_id;
        const username = data.sender || userId;
        const wasMember = !!this.members[userId];

        delete this.publicKeyCache[userId];
        delete this.signingKeyCache[userId];
        delete this.members[userId];
        if (wasMember && this.currentRoom) {
            this.roomReady = false;
        }
        this.updateMemberCount();
        this.addSystemMessage(`${username} deleted their account`);
    },

    handleRoomDeleted(data) {
        const roomId = data.room_id;
        if (!roomId) {
            void this.loadRooms();
            return;
        }
        if (this.currentRoom && this.currentRoom.id === roomId) {
            this.addSystemMessage('This room has been deleted by its creator.');
            delete this.privateRoomCodes[roomId];
            delete this.memberSnapshots[roomId];
            delete this.keyMasterRooms[roomId];
            delete this.ratchetRecoveryAcknowledged[roomId];
            delete this.roomEpochs[roomId];
            this.currentRoom = null;
            this.members = {};
            this.roomReady = false;
            document.getElementById('no-room-selected').classList.remove('hidden');
            document.getElementById('room-view').classList.add('hidden');
            document.getElementById('invite-code-section').classList.add('hidden');
        }
        delete this.privateRoomCodes[roomId];
        delete this.memberSnapshots[roomId];
        delete this.keyMasterRooms[roomId];
        delete this.ratchetRecoveryAcknowledged[roomId];
        delete this.roomEpochs[roomId];
        this.rooms = this.rooms.filter(r => r.id !== roomId);
        this.renderRoomList();
    },

    async handleChatMessage(data) {
        if (!this.currentRoom || data.room_id !== this.currentRoom.id) return;

        if (!data.signature || !data.timestamp) {
            console.error('Message missing signature or timestamp');
            return;
        }

        const generation = data.generation || 0;
        const messageNum = data.message_num || 0;

        const dedupKey = `${data.room_id}:${data.sender_id}:${generation}:${messageNum}`;
        if (this.seenMessages.has(dedupKey)) {
            return;
        }
        this.seenMessages.add(dedupKey);
        if (this.seenMessages.size > this.MAX_SEEN_MESSAGES) {
            const first = this.seenMessages.values().next().value;
            this.seenMessages.delete(first);
        }
        const requiredEpoch = this.getRoomEpoch(data.room_id);
        if (generation < requiredEpoch) {
            console.warn('Rejected message below required room epoch:', generation, requiredEpoch);
            return;
        }

        let signingKey = this.signingKeyCache[data.sender_id];
        if (!signingKey) {
            const member = this.members[data.sender_id];
            if (member && member.signing_key) {
                signingKey = Crypto.base64ToBytes(member.signing_key);
            } else {
                try {
                    const userData = await API.getUserKey(data.sender_id, this.currentRoom?.id);
                    signingKey = Crypto.base64ToBytes(userData.signing_key);
                } catch (error) {
                    console.error('Failed to fetch signing key for sender:', error);
                    return;
                }
            }
            this.signingKeyCache[data.sender_id] = signingKey;
        }

        const isValid = await Crypto.verifyMessageSignature(
            signingKey,
            data.room_id,
            data.content,
            data.timestamp,
            generation,
            messageNum,
            data.signature
        );

        if (!isValid) {
            console.error('Message signature verification failed from user:', data.sender_id);
            this.addSystemMessage(`Warning: Received message with invalid signature from ${data.sender}`);
            return;
        }

        const localGeneration = this.getLocalRatchetGeneration(data.room_id);
        if (localGeneration === 0 || generation > localGeneration) {
            if (!this.pendingKeyRequests[data.room_id]) {
                this.roomReady = false;
                void this.requestRatchetStateWithTimeout(data.room_id);
            }
            return;
        }

        try {
            const decrypted = await Crypto.decryptMessage(data.room_id, generation, messageNum, data.content);
            this.addMessage(data.sender, decrypted, data.timestamp, data.sender_id);
        } catch (error) {
            console.error('Failed to decrypt message:', error);
        }
    },

    async handleKeyRequest(data) {
        if (data.sender_id === this.currentUser.id) return;
        if (!this.currentRoom || data.room_id !== this.currentRoom.id) return;
        if (!this.keyMasterRooms[data.room_id]) return;

        const ratchet = Crypto.getRoomRatchet(data.room_id);
        if (!ratchet) return;

        await this.sendRatchetStateToUser(data.room_id, data.sender_id, 'key_request');
    },

    async handleRatchetState(data) {
        if (!data.content || !data.content.state || !data.content.user_id) return;
        if (data.content.user_id !== this.currentUser.id) return;
        if (!this.currentRoom || data.room_id !== this.currentRoom.id) return;

        try {
            const epoch = Number(data.content.epoch);
            const timestamp = Number(data.content.timestamp);
            const signature = data.content.signature;
            const hasSignature = typeof signature === 'string'
                ? signature.trim() !== ''
                : (Array.isArray(signature) && signature.length > 0);
            if (!Number.isInteger(epoch) || epoch <= 0 || !Number.isInteger(timestamp) || timestamp <= 0 || !hasSignature) {
                console.warn('Rejected ratchet_state: missing or invalid signature metadata');
                return;
            }
            const requiredEpoch = this.getRoomEpoch(data.room_id);
            if (epoch < requiredEpoch) {
                console.warn('Rejected ratchet_state below required room epoch:', epoch, requiredEpoch);
                return;
            }

            const leaderId = this.getRoomLeaderId(data.room_id);
            const senderIsExpected = data.sender_id === leaderId || !!this.pendingKeyRequests[data.room_id];
            if (!senderIsExpected) {
                console.warn('Rejected ratchet_state from non-leader sender:', data.sender_id);
                return;
            }

            let senderSigningKey = this.signingKeyCache[data.sender_id];
            if (!senderSigningKey) {
                const senderData = await API.getUserKey(data.sender_id, this.currentRoom.id);
                senderSigningKey = Crypto.base64ToBytes(senderData.signing_key);
                this.signingKeyCache[data.sender_id] = senderSigningKey;
            }

            const isSignedStateValid = await Crypto.verifyRatchetStateTransferSignature(
                senderSigningKey,
                data.room_id,
                data.content.user_id,
                data.content.state,
                epoch,
                data.content.reason || '',
                timestamp,
                signature
            );
            if (!isSignedStateValid) {
                console.warn('Rejected ratchet_state with invalid signature');
                return;
            }

            let senderKey = this.publicKeyCache[data.sender_id];
            if (!senderKey) {
                const userData = await API.getUserKey(data.sender_id, this.currentRoom.id);
                senderKey = Crypto.base64ToBytes(userData.public_key);
                this.publicKeyCache[data.sender_id] = senderKey;
            }

            const currentState = Crypto.getRatchetState(data.room_id);
            if (currentState && Number.isInteger(currentState.generation) && epoch <= currentState.generation) {
                console.warn('Rejected stale or replayed ratchet_state epoch:', epoch);
                return;
            }

            const ratchetState = await Crypto.decryptRatchetState(
                data.content.state,
                senderKey
            );
            if (!ratchetState || !Number.isInteger(ratchetState.generation) || ratchetState.generation !== epoch) {
                console.warn('Rejected ratchet_state: decrypted epoch mismatch');
                return;
            }

            await Crypto.applyRatchetState(data.room_id, ratchetState);
            this.setRoomEpoch(data.room_id, epoch);
            if (this.currentRoom && this.currentRoom.id === data.room_id) {
                this.roomReady = this.getLocalRatchetGeneration(data.room_id) >= this.getRoomEpoch(data.room_id);
            }
            this.keyMasterRooms[data.room_id] = this.isCurrentRoomLeader(data.room_id);
             
            if (this.pendingKeyRequests[data.room_id]) {
                clearTimeout(this.pendingKeyRequests[data.room_id].timer);
                delete this.pendingKeyRequests[data.room_id];
                this.addSystemMessage('Room ratchet state received. You can now send and receive messages.');
            }
        } catch (error) {
            console.error('Failed to process ratchet state:', error);
        }
    },

    async sendRatchetStateToUser(roomId, userId, reason = 'membership_change') {
        try {
            let ratchetState = Crypto.getRatchetState(roomId);
            if (!ratchetState) {
                await this.alignRatchetToEpoch(roomId, this.getRoomEpoch(roomId));
                ratchetState = Crypto.getRatchetState(roomId);
            }
            if (!ratchetState) return;

            const requiredEpoch = this.getRoomEpoch(roomId);
            if (ratchetState.generation < requiredEpoch) {
                await this.alignRatchetToEpoch(roomId, requiredEpoch);
                ratchetState = Crypto.getRatchetState(roomId);
            }
            if (!ratchetState || ratchetState.generation < requiredEpoch) {
                return;
            }

            let userKey = this.publicKeyCache[userId];
            if (!userKey) {
                const userData = await API.getUserKey(userId, roomId);
                userKey = Crypto.base64ToBytes(userData.public_key);
                this.publicKeyCache[userId] = userKey;
            }

            const encryptedState = await Crypto.encryptRatchetStateForUser(ratchetState, userKey);
            const signedTransfer = await Crypto.signRatchetStateTransfer(
                roomId,
                userId,
                encryptedState,
                ratchetState.generation,
                reason
            );

            WS.sendRatchetState(roomId, userId, encryptedState, {
                epoch: ratchetState.generation,
                reason: reason,
                timestamp: signedTransfer.timestamp,
                signature: signedTransfer.signature
            });
        } catch (error) {
            console.error('Failed to send ratchet state:', error);
        }
    },

    async sendMessage() {
        if (!this.currentRoom) return;
        if (!WS.isConnected()) {
            this.showError('Connection lost. Please wait for reconnect.');
            return;
        }
        if (!this.roomReady) {
            this.showError('Rejoining room. Please wait...');
            return;
        }

        const ratchet = Crypto.getRoomRatchet(this.currentRoom.id);
        if (!ratchet) {
            this.showError('Waiting for room ratchet state. Please wait...');
            return;
        }
        const requiredEpoch = this.getRoomEpoch(this.currentRoom.id);
        const localGeneration = this.getLocalRatchetGeneration(this.currentRoom.id);
        if (localGeneration < requiredEpoch) {
            this.roomReady = false;
            if (this.keyMasterRooms[this.currentRoom.id]) {
                await this.performMembershipRekey(this.currentRoom.id, 'epoch_sync');
            } else if (!this.pendingKeyRequests[this.currentRoom.id]) {
                void this.requestRatchetStateWithTimeout(this.currentRoom.id);
            }
            this.showError('Synchronizing room key epoch. Please wait...');
            return;
        }

        const input = document.getElementById('message-input');
        const text = input.value.trim();
        if (!text) return;

        try {
            const encrypted = await Crypto.encryptMessage(this.currentRoom.id, text);
            const { signature, timestamp, generation, messageNum } = await Crypto.signMessage(this.currentRoom.id, encrypted);
            const sent = WS.sendMessage(
                this.currentRoom.id,
                { iv: encrypted.iv, ciphertext: encrypted.ciphertext },
                signature,
                timestamp,
                generation,
                messageNum
            );
            if (!sent) {
                this.showError('Message not sent. Connection unavailable.');
                return;
            }
            this.addMessage(this.currentUser.username, text, timestamp, this.currentUser.id, true);
            input.value = '';
        } catch (error) {
            this.showError('Failed to send message');
        }
    },

    addMessage(sender, text, timestamp, senderId, isOwn = false) {
        const container = document.getElementById('messages');
        const div = document.createElement('div');
        div.className = 'message' + (isOwn ? ' own' : '');
        
        const time = new Date(timestamp).toLocaleTimeString();
        div.innerHTML = `
            <div class="message-header">
                <span class="message-sender">${this.escapeHtml(sender)}</span>
                <span class="message-time">${time}</span>
            </div>
            <div class="message-content">${this.escapeHtml(text)}</div>
        `;
        
        container.appendChild(div);
        container.scrollTop = container.scrollHeight;
    },

    addSystemMessage(text) {
        const container = document.getElementById('messages');
        const div = document.createElement('div');
        div.className = 'system-message';
        div.textContent = text;
        container.appendChild(div);
        container.scrollTop = container.scrollHeight;
    },

    async updateMembersList(roomId, members, roomEpochHint = null) {
        if (!this.currentRoom || roomId !== this.currentRoom.id || !Array.isArray(members)) {
            return;
        }
        this.setRoomEpoch(roomId, roomEpochHint);
        const requiredEpoch = this.getRoomEpoch(roomId);

        const previousMembers = Array.isArray(this.memberSnapshots[roomId])
            ? this.memberSnapshots[roomId]
            : null;

        this.members = {};
        members.forEach(m => {
            this.members[m.id] = m;
            if (m.public_key) {
                this.publicKeyCache[m.id] = Crypto.base64ToBytes(m.public_key);
            }
            if (m.signing_key) {
                this.signingKeyCache[m.id] = Crypto.base64ToBytes(m.signing_key);
            }
        });

        const currentMembers = this.getSortedMemberIDs();
        this.memberSnapshots[roomId] = currentMembers;
        this.keyMasterRooms[roomId] = this.isCurrentRoomLeader(roomId);

        if (previousMembers) {
            const addedMembers = currentMembers.filter(id => !previousMembers.includes(id));
            const removedMembers = previousMembers.filter(id => !currentMembers.includes(id));

            if (addedMembers.length > 0 || removedMembers.length > 0) {
                this.roomReady = false;
                const reason = removedMembers.length > 0 ? 'member_removed' : 'member_added';

                if (this.keyMasterRooms[roomId]) {
                    await this.performMembershipRekey(roomId, reason);
                } else if (!this.pendingKeyRequests[roomId]) {
                    void this.requestRatchetStateWithTimeout(roomId);
                }

                this.updateMemberCount();
                return;
            }
        }

        const hasRatchet = !!Crypto.getRoomRatchet(roomId);
        if (!hasRatchet) {
            const existingMembers = currentMembers.filter(id => id !== this.currentUser.id);
            this.roomReady = false;
            if (existingMembers.length === 0) {
                await this.alignRatchetToEpoch(roomId, requiredEpoch);
                this.keyMasterRooms[roomId] = true;
                this.addSystemMessage('You are the first active member. Room ratchet initialized.');
                this.roomReady = this.getLocalRatchetGeneration(roomId) >= requiredEpoch;
            } else if (!this.pendingKeyRequests[roomId]) {
                void this.requestRatchetStateWithTimeout(roomId);
            }
        } else {
            const localGeneration = this.getLocalRatchetGeneration(roomId);
            if (localGeneration < requiredEpoch) {
                this.roomReady = false;
                if (this.keyMasterRooms[roomId]) {
                    await this.performMembershipRekey(roomId, 'epoch_sync');
                } else if (!this.pendingKeyRequests[roomId]) {
                    void this.requestRatchetStateWithTimeout(roomId);
                }
            } else {
                this.roomReady = true;
            }
        }

        this.updateMemberCount();
    },

    updateMemberCount() {
        const count = Object.keys(this.members).length;
        document.getElementById('member-count').textContent = `${count} member${count !== 1 ? 's' : ''}`;
        
        const names = Object.values(this.members).map(m => m.username).join(', ');
        document.getElementById('members-list').textContent = names;
    },

    showCreateRoomModal() {
        document.getElementById('create-room-modal').classList.remove('hidden');
        document.getElementById('room-name-input').value = '';
        document.getElementById('room-private-checkbox').checked = false;
        document.getElementById('room-name-input').focus();
    },

    hideCreateRoomModal() {
        document.getElementById('create-room-modal').classList.add('hidden');
    },

    async createRoom() {
        const name = document.getElementById('room-name-input').value.trim();
        const isPrivate = document.getElementById('room-private-checkbox').checked;
        
        if (!name) {
            this.showError('Please enter a room name');
            return;
        }

        if (name.length > 64) {
            this.showError('Room name must be 64 characters or less');
            return;
        }

        try {
            const room = await API.createRoom(name, isPrivate);
            this.hideCreateRoomModal();
            await this.loadRooms();
            await this.joinRoomInternal(room, isPrivate ? room.invite_code : null);
            
            if (room.invite_code) {
                this.showInviteCodeSuccess(room.invite_code);
            }
        } catch (error) {
            this.showError(error.message || 'Failed to create room');
        }
    },

    showInviteCodeSuccess(code) {
        this.showError(`Room created! Invite code: ${code}`, true);
    },

    copyInviteCode() {
        const code = document.getElementById('invite-code-display').textContent;
        navigator.clipboard.writeText(code).then(() => {
            this.showError('Invite code copied to clipboard!', true);
        }).catch(() => {
            this.showError('Failed to copy invite code');
        });
    },

    async regenerateInviteCode() {
        if (!this.currentRoom) return;
        
        try {
            const result = await API.regenerateInviteCode(this.currentRoom.id);
            document.getElementById('invite-code-display').textContent = result.invite_code;
            this.currentRoom.invite_code = result.invite_code;
            this.showError('New invite code generated!', true);
        } catch (error) {
            this.showError(error.message || 'Failed to regenerate code');
        }
    },

    showJoinByCodeModal() {
        document.getElementById('join-by-code-modal').classList.remove('hidden');
        document.getElementById('invite-code-input').value = '';
        document.getElementById('invite-code-input').focus();
    },

    hideJoinByCodeModal() {
        document.getElementById('join-by-code-modal').classList.add('hidden');
    },

    async joinByCode() {
        const code = document.getElementById('invite-code-input').value.trim();
        if (!code) {
            this.showError('Please enter an invite code');
            return;
        }

        try {
            const result = await API.joinRoomByCode(code);
            this.hideJoinByCodeModal();
            await this.loadRooms();
            
            const room = { id: result.room_id, name: result.name, is_private: true, current_epoch: result.current_epoch };
            await this.joinRoomInternal(room, code);
        } catch (error) {
            this.showError(error.message || 'Invalid invite code');
        }
    },

    showAccountSettings() {
        document.getElementById('account-settings-modal').classList.remove('hidden');
    },

    hideAccountSettings() {
        document.getElementById('account-settings-modal').classList.add('hidden');
    },

    async deleteAccount() {
        this.hideAccountSettings();

        if (!confirm('Are you sure you want to delete your account? This will permanently delete your account and all rooms you created. This action cannot be undone.')) {
            return;
        }

        const password = await this.showInputModal('Delete Account', 'Password', 'Enter your account password', 'password');
        if (!password) return;

        try {
            // Step 1: Initiate deletion (password verification + challenge)
            const challenge = await API.deleteAccount(password, 'DELETE');

            // Step 2: Sign challenge with current key
            const signature = await Crypto.signChallenge(challenge.nonce, challenge.user_id);

            // Step 3: Confirm deletion
            await API.confirmDeleteAccount(challenge.nonce, signature);

            // Cleanup local state
            WS.disconnect();
            await Crypto.deleteStoredKeyPair();
            this.currentUser = null;
            this.currentRoom = null;
            this.members = {};
            this.publicKeyCache = {};
            this.signingKeyCache = {};
            this.keyMasterRooms = {};
            this.ratchetRecoveryAcknowledged = {};
            this.pendingKeyRequests = {};
            this.privateRoomCodes = {};
            this.memberSnapshots = {};
            this.roomEpochs = {};
            this.keyPassword = null;
            this.pendingRotationContext = null;
            this.roomReady = false;
            document.getElementById('chat-screen').classList.add('hidden');
            document.getElementById('auth-screen').classList.remove('hidden');
            document.getElementById('username').value = '';
            document.getElementById('password').value = '';

            this.showError('Account deleted successfully', true);
        } catch (error) {
            this.showError(error.message || 'Failed to delete account');
        }
    },

    async rotateKeys() {
        this.hideAccountSettings();

        const accountPassword = await this.showInputModal('Rotate Keys', 'Password', 'Enter your account password', 'password');
        if (!accountPassword) return;

        try {
            const challenge = await API.rotateKeys(accountPassword);
            const signature = await Crypto.signChallenge(challenge.nonce, challenge.user_id);

            const newKeyPair = await Crypto.generateKeyPairStandalone();
            const newSigningKeyPair = await Crypto.generateSigningKeyPairStandalone();

            this.pendingRotationContext = {
                challenge: challenge,
                signature: signature,
                newKeyPair: newKeyPair,
                newSigningKeyPair: newSigningKeyPair
            };
            this.pendingAuthMode = 'rotate';
            this.showPasswordModal('set');
        } catch (error) {
            this.pendingRotationContext = null;
            this.pendingAuthMode = null;
            this.showError(error.message || 'Failed to rotate keys');
        }
    },

    async logout() {
        WS.disconnect();
        try {
            await API.logout();
        } catch {}
        Crypto.clearRuntimeState();
        this.currentUser = null;
        this.currentRoom = null;
        this.members = {};
        this.publicKeyCache = {};
        this.signingKeyCache = {};
        this.keyMasterRooms = {};
        this.ratchetRecoveryAcknowledged = {};
        this.pendingKeyRequests = {};
        this.privateRoomCodes = {};
        this.memberSnapshots = {};
        this.roomEpochs = {};
        this.keyPassword = null;
        this.pendingRotationContext = null;
        this.roomReady = false;
        document.getElementById('chat-screen').classList.add('hidden');
        document.getElementById('auth-screen').classList.remove('hidden');
        document.getElementById('username').value = '';
        document.getElementById('password').value = '';
    },

    showError(message, isSuccess = false) {
        const existing = document.querySelector('.error-toast');
        if (existing) existing.remove();

        const toast = document.createElement('div');
        toast.className = 'error-toast';
        if (isSuccess) toast.style.background = '#4caf50';
        toast.textContent = message;
        document.body.appendChild(toast);

        setTimeout(() => toast.remove(), 3000);
    },

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
};

document.addEventListener('DOMContentLoaded', () => App.init());

