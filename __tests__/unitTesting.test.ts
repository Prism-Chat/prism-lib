import { Prism } from '../src/Prism';

describe('Unit testing.', () => {
	let alice: Prism;
	let bob: Prism;

	beforeEach(() => {
		alice = new Prism();
		alice.generateKeyPair();

		bob = new Prism();
		bob.generateKeyPair();
	});

	afterEach(() => {});

	test('Test generating RSA Keys.', () => {
		expect(alice.publicKey).not.toEqual('');
		expect(alice.privateKey).not.toEqual('');
	});

	test('Test RSA encrypt and decrypt.', () => {
		let testObject = {
			message: 'test',
		};

		let encrypted = alice.publicEncrypt(testObject, bob.publicKey);
		let decrypted = bob.privateDecrypt(encrypted);

		expect(decrypted).toEqual(testObject);
	});

	test('Test RSA sign and verify.', () => {
		let testObject = {
			message: 'test',
		};

		let signed = alice.sign(testObject);
		let verified = bob.verify(testObject, signed, alice.publicKey);

		expect(verified).toEqual(true);
	});

	test('Test symmetric encrypt and decrypt.', () => {
		let testObject = {
			message: 'test',
		};
		let key = alice.generateKey();

		let encrypted = alice.encrypt(testObject, key);
		let decrypted = bob.decrypt(encrypted, key);

		expect(decrypted).toEqual(testObject);
	});

	test('Test write and read message.', () => {
		let testObject = {
			sender: alice.publicKey,
			type: 'message',
			data: {
				message: 'test',
			},
		};

		let writtenMessage = alice.writeMessage(bob.publicKey, testObject);
		let readMessage = bob.readMessage(writtenMessage);

		expect(readMessage).toEqual(testObject);
	});
});
