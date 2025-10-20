import { ICodec, ICommunicationManager, IConnection, IConnectionStateListener, IMessageComposer, IMessageConfiguration, IMessageDataWrapper, IMessageEvent, NitroConfiguration, NitroLogger, WebSocketEventEnum } from '../../api';
import { SocketConnectionEvent } from '../../events';
import { EventDispatcher } from '../common';
import { EvaWireFormat } from './codec';
import { MessageClassManager } from './messages';
import { PacketEncryption } from './PacketEncryption';

export class SocketConnection extends EventDispatcher implements IConnection
{
    private _communicationManager: ICommunicationManager;
    private _stateListener: IConnectionStateListener;
    private _socket: WebSocket;
    private _messages: MessageClassManager;
    private _codec: ICodec;
    private _dataBuffer: ArrayBuffer;
    private _isReady: boolean;

    private _pendingClientMessages: IMessageComposer<unknown[]>[];
    private _pendingServerMessages: IMessageDataWrapper[];

    private _isAuthenticated: boolean;
    private _encryption: PacketEncryption | null;
    private _handshakeComplete: boolean;

    constructor(communicationManager: ICommunicationManager, stateListener: IConnectionStateListener)
    {
        super();

        this._communicationManager = communicationManager;
        this._stateListener = stateListener;
        this._socket = null;
        this._messages = new MessageClassManager();
        this._codec = new EvaWireFormat();
        this._dataBuffer = null;
        this._isReady = false;

        this._pendingClientMessages = [];
        this._pendingServerMessages = [];

        this._isAuthenticated = false;
        this._encryption = null;
        this._handshakeComplete = false;

        this.onOpen = this.onOpen.bind(this);
        this.onClose = this.onClose.bind(this);
        this.onError = this.onError.bind(this);
        this.onMessage = this.onMessage.bind(this);
    }

    public init(socketUrl: string): void
    {
        if(this._stateListener)
        {
            this._stateListener.connectionInit(socketUrl);
        }

        this.createSocket(socketUrl);
    }

    protected onDispose(): void
    {
        super.onDispose();

        this.destroySocket();

        if(this._encryption)
        {
            this._encryption.dispose();
            this._encryption = null;
        }

        this._communicationManager = null;
        this._stateListener = null;
        this._messages = null;
        this._codec = null;
        this._dataBuffer = null;
    }

    /**
     * Performs encryption handshake with server:
     * 1. Receive server's public key (4-byte length + public key)
     * 2. Send client's public key (4-byte length + public key)
     * 3. Derive shared secret and initialize encryption
     */
    private async performEncryptionHandshake(): Promise<void>
    {
        try
        {
            // Initialize encryption
            this._encryption = new PacketEncryption();
            await this._encryption.initialize();

            // Wait for server's public key (first message)
            const serverPublicKeyData = await this.waitForHandshakeMessage();
            
            NitroLogger.log('[Encryption] Received server public key (' + serverPublicKeyData.byteLength + ' bytes)');

            // Send client's public key
            const clientPublicKey = await this._encryption.getPublicKey();
            const sendBuffer = new ArrayBuffer(4 + clientPublicKey.byteLength);
            const sendView = new DataView(sendBuffer);
            
            // Write length prefix (big-endian)
            sendView.setUint32(0, clientPublicKey.byteLength, false);
            
            // Copy public key
            new Uint8Array(sendBuffer, 4).set(new Uint8Array(clientPublicKey));
            
            this._socket.send(sendBuffer);
            NitroLogger.log('[Encryption] Sent client public key (' + clientPublicKey.byteLength + ' bytes)');

            // Complete key exchange
            await this._encryption.completeKeyExchange(serverPublicKeyData);
            
            this._handshakeComplete = true;
        }
        catch(error)
        {
            throw new Error('Encryption handshake failed: ' + error);
        }
    }

    /**
     * Waits for and processes a single handshake message
     */
    private waitForHandshakeMessage(): Promise<ArrayBuffer>
    {
        return new Promise((resolve, reject) =>
        {
            const timeout = setTimeout(() =>
            {
                this._socket.removeEventListener('message', messageHandler);
                reject(new Error('Handshake timeout'));
            }, 10000); // 10 second timeout

            const messageHandler = (event: MessageEvent) =>
            {
                clearTimeout(timeout);
                this._socket.removeEventListener('message', messageHandler);

                const reader = new FileReader();
                reader.readAsArrayBuffer(event.data);
                reader.onloadend = () =>
                {
                    const data = reader.result as ArrayBuffer;
                    
                    if(data.byteLength < 4)
                    {
                        reject(new Error('Invalid handshake message'));
                        return;
                    }

                    // Read length prefix
                    const view = new DataView(data);
                    const length = view.getUint32(0, false); // big-endian
                    
                    if(data.byteLength < 4 + length)
                    {
                        reject(new Error('Incomplete handshake message'));
                        return;
                    }

                    // Extract public key
                    const publicKey = data.slice(4, 4 + length);
                    resolve(publicKey);
                };
            };

            this._socket.addEventListener('message', messageHandler);
        });
    }

    public onReady(): void
    {
        if(this._isReady) return;

        this._isReady = true;

        if(this._pendingServerMessages && this._pendingServerMessages.length) this.processWrappers(...this._pendingServerMessages);

        if(this._pendingClientMessages && this._pendingClientMessages.length) this.send(...this._pendingClientMessages);

        this._pendingServerMessages = [];
        this._pendingClientMessages = [];
    }

    private createSocket(socketUrl: string): void
    {
        if(!socketUrl) return;

        this.destroySocket();

        this._dataBuffer = new ArrayBuffer(0);
        this._socket = new WebSocket(socketUrl);

        this._socket.addEventListener(WebSocketEventEnum.CONNECTION_OPENED, this.onOpen);
        this._socket.addEventListener(WebSocketEventEnum.CONNECTION_CLOSED, this.onClose);
        this._socket.addEventListener(WebSocketEventEnum.CONNECTION_ERROR, this.onError);
        this._socket.addEventListener(WebSocketEventEnum.CONNECTION_MESSAGE, this.onMessage);
    }

    private destroySocket(): void
    {
        if(!this._socket) return;

        this._socket.removeEventListener(WebSocketEventEnum.CONNECTION_OPENED, this.onOpen);
        this._socket.removeEventListener(WebSocketEventEnum.CONNECTION_CLOSED, this.onClose);
        this._socket.removeEventListener(WebSocketEventEnum.CONNECTION_ERROR, this.onError);
        this._socket.removeEventListener(WebSocketEventEnum.CONNECTION_MESSAGE, this.onMessage);

        if(this._socket.readyState === WebSocket.OPEN) this._socket.close();

        this._socket = null;
    }

    private onOpen(event: Event): void
    {
        // Check if encryption is enabled in config
        const encryptionEnabled = NitroConfiguration.getValue<boolean>('packet.encryption.enabled', false);
        
        if(encryptionEnabled)
        {
            // Check if in secure context (required for Web Crypto API)
            if(!window.isSecureContext)
            {
                NitroLogger.error('[Encryption] Not in secure context. Encryption requires HTTPS or localhost!');
                NitroLogger.error('[Encryption] Current URL:', window.location.href);
                NitroLogger.error('[Encryption] Falling back to unencrypted connection (bypassed)...');
                this._handshakeComplete = true; // Skip encryption
                this.dispatchConnectionEvent(SocketConnectionEvent.CONNECTION_OPENED, event);
                return;
            }

            // Start encryption handshake when connection opens
            this.performEncryptionHandshake().then(() =>
            {
                NitroLogger.log('[Encryption] ✅ Handshake completed - All packets are now ENCRYPTED with AES-256-GCM');
                this.dispatchConnectionEvent(SocketConnectionEvent.CONNECTION_OPENED, event);
            }).catch((error) =>
            {
                NitroLogger.error('[Encryption] Handshake failed:', error);
                this._socket?.close();
            });
        }
        else
        {
            NitroLogger.log('[Encryption] Packet encryption is DISABLED - connection is NOT encrypted (bypassed)');
            this._handshakeComplete = true; // Skip encryption
            this.dispatchConnectionEvent(SocketConnectionEvent.CONNECTION_OPENED, event);
        }
    }

    private onClose(event: CloseEvent): void
    {
        this.dispatchConnectionEvent(SocketConnectionEvent.CONNECTION_CLOSED, event);
    }

    private onError(event: Event): void
    {
        this.dispatchConnectionEvent(SocketConnectionEvent.CONNECTION_ERROR, event);
    }

    private onMessage(event: MessageEvent): void
    {
        if(!event) return;

        const reader = new FileReader();

        reader.readAsArrayBuffer(event.data);

        reader.onloadend = async () =>
        {
            let receivedData = reader.result as ArrayBuffer;

            // If handshake is complete and encryption is initialized, decrypt the data
            if(this._handshakeComplete && this._encryption && this._encryption.isInitialized)
            {
                try
                {
                    receivedData = await this._encryption.decrypt(receivedData);
                }
                catch(error)
                {
                    NitroLogger.error('[Encryption] Failed to decrypt packet:', error);
                    return;
                }
            }

            this._dataBuffer = this.concatArrayBuffers(this._dataBuffer, receivedData);

            this.processReceivedData();
        };
    }

    private dispatchConnectionEvent(type: string, event: Event): void
    {
        this.dispatchEvent(new SocketConnectionEvent(type, this, event));
    }

    public authenticated(): void
    {
        this._isAuthenticated = true;
    }

    public send(...composers: IMessageComposer<unknown[]>[]): boolean
    {
        if(this.disposed || !composers) return false;

        composers = [...composers];

        if(this._isAuthenticated && !this._isReady)
        {
            if(!this._pendingClientMessages) this._pendingClientMessages = [];

            this._pendingClientMessages.push(...composers);

            return false;
        }

        for(const composer of composers)
        {
            if(!composer) continue;

            const header = this._messages.getComposerId(composer);

            if(header === -1)
            {
                NitroLogger.packets('Unknown Composer', composer.constructor.name);

                continue;
            }

            const message = composer.getMessageArray();
            const encoded = this._codec.encode(header, message);

            if(!encoded)
            {
                NitroLogger.packets('Encoding Failed', composer.constructor.name);

                continue;
            }

            NitroLogger.packets('OutgoingComposer', header, composer.constructor.name, message);

            this.write(encoded.getBuffer());
        }

        return true;
    }

    private async write(buffer: ArrayBuffer): Promise<void>
    {
        if(this._socket.readyState !== WebSocket.OPEN) return;

        // If handshake is complete and encryption is initialized, encrypt the data
        if(this._handshakeComplete && this._encryption && this._encryption.isInitialized)
        {
            try
            {
                buffer = await this._encryption.encrypt(buffer);
            }
            catch(error)
            {
                NitroLogger.error('[Encryption] Failed to encrypt packet:', error);
                return;
            }
        }

        this._socket.send(buffer);
    }

    public processReceivedData(): void
    {
        try
        {
            this.processData();
        }

        catch (err)
        {
            NitroLogger.error(err);
        }
    }

    private processData(): void
    {
        const wrappers = this.splitReceivedMessages();

        if(!wrappers || !wrappers.length) return;

        if(this._isAuthenticated && !this._isReady)
        {
            if(!this._pendingServerMessages) this._pendingServerMessages = [];

            this._pendingServerMessages.push(...wrappers);

            return;
        }

        this.processWrappers(...wrappers);
    }

    private processWrappers(...wrappers: IMessageDataWrapper[]): void
    {
        if(!wrappers || !wrappers.length) return;

        for(const wrapper of wrappers)
        {
            if(!wrapper) continue;

            const messages = this.getMessagesForWrapper(wrapper);

            if(!messages || !messages.length) continue;

            NitroLogger.packets('IncomingMessage', wrapper.header, messages[0].constructor.name, messages[0].parser);

            this.handleMessages(...messages);
        }
    }

    private splitReceivedMessages(): IMessageDataWrapper[]
    {
        if(!this._dataBuffer || !this._dataBuffer.byteLength) return null;

        return this._codec.decode(this);
    }

    private concatArrayBuffers(buffer1: ArrayBuffer, buffer2: ArrayBuffer): ArrayBuffer
    {
        const array = new Uint8Array(buffer1.byteLength + buffer2.byteLength);

        array.set(new Uint8Array(buffer1), 0);
        array.set(new Uint8Array(buffer2), buffer1.byteLength);

        return array.buffer;
    }

    private getMessagesForWrapper(wrapper: IMessageDataWrapper): IMessageEvent[]
    {
        if(!wrapper) return null;

        const events = this._messages.getEvents(wrapper.header);

        if(!events || !events.length)
        {
            NitroLogger.packets('IncomingMessage', wrapper.header, 'UNREGISTERED', wrapper);

            return;
        }

        try
        {
            //@ts-ignore
            const parser = new events[0].parserClass();

            if(!parser || !parser.flush() || !parser.parse(wrapper)) return null;

            for(const event of events) (event.parser = parser);
        }

        catch (e)
        {
            NitroLogger.error('Error parsing message', e, events[0].constructor.name);

            return null;
        }

        return events;
    }

    private handleMessages(...messages: IMessageEvent[]): void
    {
        messages = [...messages];

        for(const message of messages)
        {
            if(!message) continue;

            message.connection = this;

            if(message.callBack) message.callBack(message);
        }
    }

    public registerMessages(configuration: IMessageConfiguration): void
    {
        if(!configuration) return;

        this._messages.registerMessages(configuration);
    }

    public addMessageEvent(event: IMessageEvent): void
    {
        if(!event || !this._messages) return;

        this._messages.registerMessageEvent(event);
    }

    public removeMessageEvent(event: IMessageEvent): void
    {
        if(!event || !this._messages) return;

        this._messages.removeMessageEvent(event);
    }

    public get isAuthenticated(): boolean
    {
        return this._isAuthenticated;
    }

    public get dataBuffer(): ArrayBuffer
    {
        return this._dataBuffer;
    }

    public set dataBuffer(buffer: ArrayBuffer)
    {
        this._dataBuffer = buffer;
    }
}
