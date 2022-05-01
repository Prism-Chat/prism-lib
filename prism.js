const crypto = require('crypto');

class Prism {
	constructor(publicKey = null, privateKey = null) {
		this.publicKey = publicKey;
		this.privateKey = privateKey;
	}

	generateKeyPair(modulusLength = 4096) {
		const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
			modulusLength: modulusLength,
			publicKeyEncoding: {
				type: 'spki',
				format: 'der',
			},
			privateKeyEncoding: {
				type: 'pkcs8',
				format: 'der',
			},
		});

		this.publicKey = publicKey.toString('base64');
		this.privateKey = privateKey.toString('base64');

		return {
			publicKey: this.publicKey,
			privateKey: this.privateKey,
		};
	}

	generateKey(min = 1024, max = 2048) {
		return crypto
			.generateKeySync('hmac', {
				length: Math.floor(Math.random() * (max - min + 1)) + min,
			})
			.export()
			.toString('base64');
	}

	privateEncrypt(data, privateKey = this.privateKey) {
		return crypto
			.privateEncrypt(this.toPem(privateKey, 'private'), JSON.stringify(data))
			.toString('base64');
	}

	publicDecrypt(data, publicKey = this.publicKey) {
		return JSON.parse(
			crypto
				.publicDecrypt(
					this.toPem(publicKey, 'public'),
					Buffer.from(data, 'base64')
				)
				.toString()
		);
	}

	publicEncrypt(data, publicKey = this.publicKey) {
		return crypto
			.publicEncrypt(this.toPem(publicKey, 'public'), JSON.stringify(data))
			.toString('base64');
	}

	privateDecrypt(data, privateKey = this.privateKey) {
		return JSON.parse(
			crypto
				.privateDecrypt(
					this.toPem(privateKey, 'private'),
					Buffer.from(data, 'base64')
				)
				.toString()
		);
	}

	sign(data, privateKey = this.privateKey) {
		return crypto
			.sign('SHA256', JSON.stringify(data), this.toPem(privateKey, 'private'))
			.toString('base64');
	}

	verify(data, signature, publicKey = this.publicKey) {
		return crypto.verify(
			'SHA256',
			JSON.stringify(data),
			this.toPem(publicKey, 'public'),
			Buffer.from(signature, 'base64')
		);
	}

	encrypt(data, key) {
		let iv = crypto.randomBytes(16);
		let sha256 = crypto.createHash('sha256').update(key);
		let cipher = crypto.createCipheriv('aes-256-cbc', sha256.digest(), iv);
		let cipherText = cipher.update(Buffer.from(JSON.stringify(data)));
		let encrypted = Buffer.concat([iv, cipherText, cipher.final()]).toString(
			'base64'
		);
		return encrypted;
	}

	decrypt(data, key) {
		let sha256 = crypto.createHash('sha256').update(key);
		let input = Buffer.from(data, 'base64');
		let iv = input.slice(0, 16);
		let decipher = crypto.createDecipheriv('aes-256-cbc', sha256.digest(), iv);
		let cipherText = input.slice(16);
		let output = decipher.update(cipherText) + decipher.final();
		return JSON.parse(output);
	}

	toPem(key, type) {
		let parsed = '';
		while (key.length > 0) {
			parsed += key.substring(0, 64) + '\n';
			key = key.substring(64);
		}
		return `-----BEGIN ${type.toUpperCase()} KEY-----\n${parsed}-----END ${type.toUpperCase()} KEY-----`;
	}
}

module.exports = Prism;
