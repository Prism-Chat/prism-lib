import * as crypto from 'crypto';

// Prism interface defining the main data transition packet.
interface IPrism {
	sender: string;
	type: string;
	data: any;
}

// Prism encryption class
class Prism {
	// Define Prism keys
	public publicKey: string;
	public privateKey: string;

	// Assign keys from constructor to state
	constructor(publicKey: string = '', privateKey: string = '') {
		this.publicKey = publicKey;
		this.privateKey = privateKey;
	}

	// Generates an RSA keypair to be used as your identity key
	public generateKeyPair() {
		// Generate keys
		const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
			modulusLength: 4096,
			publicKeyEncoding: {
				type: 'spki',
				format: 'der',
			},
			privateKeyEncoding: {
				type: 'pkcs8',
				format: 'der',
			},
		});

		// Assign keys to state
		this.publicKey = publicKey.toString('base64');
		this.privateKey = privateKey.toString('base64');

		// Return keys
		return {
			publicKey: this.publicKey,
			privateKey: this.privateKey,
		};
	}

	// Create random key to be used in symmetric encryption
	public generateKey() {
		return crypto
			.randomBytes(Math.floor(Math.random() * (256 - 128 + 1)) + 128)
			.toString('base64');
	}

	// Encrypt data with a public RSA key
	public publicEncrypt(data: any, publicKey: string) {
		return crypto
			.publicEncrypt(
				this.toPem(publicKey, 'public'),
				Buffer.from(JSON.stringify(data))
			)
			.toString('base64');
	}

	// Decrypt data with a private RSA key
	public privateDecrypt(data: string) {
		return JSON.parse(
			crypto
				.privateDecrypt(
					this.toPem(this.privateKey, 'private'),
					Buffer.from(data, 'base64')
				)
				.toString()
		);
	}

	// Sign data with a private RSA key
	public sign(data: any) {
		return crypto
			.sign(
				'SHA256',
				Buffer.from(JSON.stringify(data)),
				this.toPem(this.privateKey, 'private')
			)
			.toString('base64');
	}

	// Verify that a piece of data was signed by the owner of a public key
	public verify(data: any, signature: string, publicKey: string) {
		return crypto.verify(
			'SHA256',
			Buffer.from(JSON.stringify(data)),
			this.toPem(publicKey, 'public'),
			Buffer.from(signature, 'base64')
		);
	}

	// Encrypt data with a symmetric key
	public encrypt(data: any, key: string) {
		let iv = crypto.randomBytes(16);
		let cipher = crypto.createCipheriv(
			'aes-256-cbc',
			crypto.createHash('sha256').update(key).digest(),
			iv
		);
		let cipherText = cipher.update(Buffer.from(JSON.stringify(data)));
		return Buffer.concat([iv, cipherText, cipher.final()]).toString('base64');
	}

	// Decrypt data with a symmetric key
	public decrypt(data: any, key: string) {
		let input = Buffer.from(data, 'base64');
		let decipher = crypto.createDecipheriv(
			'aes-256-cbc',
			crypto.createHash('sha256').update(key).digest(),
			input.slice(0, 16)
		);
		let output =
			decipher.update(input.slice(16)).toString() + decipher.final().toString();
		return JSON.parse(output);
	}

	// Convert RSA keys from Base64 format to a pem file format
	public toPem(key: string, type: string) {
		let parsed = '';
		while (key.length > 0) {
			parsed += key.substring(0, 64) + '\n';
			key = key.substring(64);
		}
		return `-----BEGIN ${type.toUpperCase()} KEY-----\n${parsed}-----END ${type.toUpperCase()} KEY-----`;
	}

	// Create a standard Prism message
	public writeMessage(recipientPublicKey: string, prismObject: IPrism) {
		let messageKey = this.generateKey();
		let messageKeyEncrypted = this.publicEncrypt(
			messageKey,
			recipientPublicKey
		);
		let messageObjectEncrypted = this.encrypt(prismObject, messageKey);
		return `${messageKeyEncrypted}:${messageObjectEncrypted}`;
	}

	// Read a standard Prism message
	public readMessage(packet: string) {
		let [encryptedSymmetricKey, encryptedPrismObject] = packet.split(':');
		let messageKey = this.privateDecrypt(encryptedSymmetricKey);
		let messageObject = this.decrypt(encryptedPrismObject, messageKey);
		return messageObject;
	}
}

// Export Prism object as well as interface
export { Prism, IPrism };
