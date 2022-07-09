import _sodium from 'libsodium-wrappers';

// Prism interface defining the main data transition packet.
interface IPrismPacket {
	sender: string;
	type: string;
	timestamp: number;
	data: any;
}

// Prism encryption class
class Prism {
	// Define Prism keys
	private publicKey: any;
	private privateKey: any;
	private sodium: any;

	// Get object containing keys in base64 format.
	get keys() {
		return {
			publicKey: this.sodium.to_base64(this.publicKey),
			privateKey: this.sodium.to_base64(this.privateKey),
		};
	}

	// Assign keys from constructor to state
	constructor() {}

	// Init async function to await sodium load
	public async init(publicKey: string = '', privateKey: string = '') {
		await _sodium.ready;
		this.sodium = _sodium;

		if (publicKey === '' || privateKey === '') {
			let keys = this.generateKeyPair();
			this.publicKey = keys.publicKey;
			this.privateKey = keys.privateKey;
		} else {
			this.publicKey = this.sodium.from_base64(publicKey);
			this.privateKey = this.sodium.from_base64(privateKey);
		}
	}

	// Generates a key to be used for symmetric encryption
	public generateKey(): any {
		const data = this.sodium.crypto_aead_chacha20poly1305_keygen();
		return this.sodium.to_base64(data);
	}

	// Generates a key pair to be used as your identity key
	private generateKeyPair() {
		const { publicKey, privateKey } = this.sodium.crypto_box_keypair();
		return {
			publicKey,
			privateKey,
		};
	}

	// Encrypt data with a symmetric key
	public encrypt(data: any, key: string): any {
		let publicNonce = this.sodium.randombytes_buf(
			this.sodium.crypto_aead_chacha20poly1305_NPUBBYTES
		);

		let cypher = this.sodium.crypto_aead_chacha20poly1305_encrypt(
			JSON.stringify(data),
			null,
			null,
			publicNonce,
			this.sodium.from_base64(key)
		);

		return {
			publicNonce: this.sodium.to_base64(publicNonce),
			cypher: this.sodium.to_base64(cypher),
		};
	}

	// Decrypt data with a symmetric key
	public decrypt(data: string, key: string, publicNonce: string): any {
		let decrypted = this.sodium.crypto_aead_chacha20poly1305_decrypt(
			null,
			this.sodium.from_base64(data),
			null,
			this.sodium.from_base64(publicNonce),
			this.sodium.from_base64(key)
		);

		return JSON.parse(this.sodium.to_string(decrypted));
	}

	// Encrypt data with a public identity key
	public encryptPublic(data: any, recipientPublicKey: any): any {
		return this.sodium.to_base64(
			this.sodium.crypto_box_seal(
				JSON.stringify(data),
				this.sodium.from_base64(recipientPublicKey)
			)
		);
	}

	// Decrypt data with a private identity key
	public decryptPrivate(data: string): any {
		return JSON.parse(
			this.sodium.to_string(
				this.sodium.crypto_box_seal_open(
					this.sodium.from_base64(data),
					this.publicKey,
					this.privateKey
				)
			)
		);
	}

	// Create encryption box
	public encryptBox(data: any, recipientPublicKey: string) {
		let nonce = this.sodium.randombytes_buf(this.sodium.crypto_box_NONCEBYTES);
		let cypher = this.sodium.crypto_box_easy(
			JSON.stringify(data),
			nonce,
			this.sodium.from_base64(recipientPublicKey),
			this.privateKey
		);
		return {
			nonce: this.sodium.to_base64(nonce),
			cypher: this.sodium.to_base64(cypher),
		};
	}

	// Decrypt an encryption box
	public decryptBox(data: string, nonce: number, senderPublicKey: string) {
		let decryptedPacket = this.sodium.crypto_box_open_easy(
			this.sodium.from_base64(data),
			this.sodium.from_base64(nonce),
			this.sodium.from_base64(senderPublicKey),
			this.privateKey
		);
		return JSON.parse(this.sodium.to_string(decryptedPacket));
	}

	// Generate key pair to later perform a key exchange
	public generateKeyExchangePair() {
		let keyPair = this.sodium.crypto_kx_keypair();
		return {
			publicKey: this.sodium.to_base64(keyPair.publicKey),
			privateKey: this.sodium.to_base64(keyPair.privateKey),
		};
	}

	// This function is to be used to preform a key exchange if you made the initial communication
	public keyExchangeIC(
		keyExchangePublicKey: string,
		keyExchangePrivatekey: string,
		receivedPublicKey: string
	) {
		let sessionKeys = this.sodium.crypto_kx_client_session_keys(
			this.sodium.from_base64(keyExchangePublicKey),
			this.sodium.from_base64(keyExchangePrivatekey),
			this.sodium.from_base64(receivedPublicKey)
		);
		return {
			receiveKey: this.sodium.to_base64(sessionKeys.sharedRx),
			sendKey: this.sodium.to_base64(sessionKeys.sharedTx),
		};
	}

	// This function is to be used to preform a key exchange if you are responding to the initial communication
	public keyExchangeRC(
		keyExchangePublicKey: string,
		keyExchangePrivatekey: string,
		receivedPublicKey: string
	) {
		let sessionKeys = this.sodium.crypto_kx_server_session_keys(
			this.sodium.from_base64(keyExchangePublicKey),
			this.sodium.from_base64(keyExchangePrivatekey),
			this.sodium.from_base64(receivedPublicKey)
		);
		return {
			receiveKey: this.sodium.to_base64(sessionKeys.sharedRx),
			sendKey: this.sodium.to_base64(sessionKeys.sharedTx),
		};
	}

	// Morph existing key in repeatable way.
	public keyDerivation(key: string) {
		const settings = {
			subKeyLength: 32,
			subKeyId: 1,
			subKeyCtx: 'prism___',
		};

		let newKey = this.sodium.crypto_kdf_derive_from_key(
			settings.subKeyLength,
			settings.subKeyId,
			settings.subKeyCtx,
			this.sodium.from_base64(key)
		);

		return this.sodium.to_base64(newKey);
	}
}

// Export Prism object as well as interface
export { Prism, IPrismPacket };
