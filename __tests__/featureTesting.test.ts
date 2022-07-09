import { Prism } from '../src/Prism';

describe('Feature testing.', () => {
	let alice: Prism;
	let bob: Prism;

	beforeEach(async () => {
		alice = new Prism();
		await alice.init();

		bob = new Prism();
		await bob.init();
	});

	afterEach(() => {});

	test('Test generating RSA Keys.', () => {
		expect(alice.keys.publicKey).not.toEqual('');
		expect(alice.keys.privateKey).not.toEqual('');
	});

	test('Format data packet.', () => {
		// Create key exchange pair for chat
		let aliceSessionPair = alice.generateKeyExchangePair();
		let bobSessionPair = alice.generateKeyExchangePair();

		// alice preforms key exchange
		let aliceSharedKeys = alice.keyExchangeIC(
			aliceSessionPair.publicKey,
			aliceSessionPair.privateKey,
			bobSessionPair.publicKey
		);

		// bob performs key exchange
		let bobSharedKeys = bob.keyExchangeRC(
			bobSessionPair.publicKey,
			bobSessionPair.privateKey,
			aliceSessionPair.publicKey
		);

		// define test object
		let testObj = {
			message: 'Hello World!',
		};

		// Encrypt test object with shared session key
		let encryptedData = alice.encrypt(testObj, aliceSharedKeys.sendKey);

		// Put session encrypted data in transport packet
		let encryptedTransportPacket = alice.createTransportPacket(
			encryptedData.cypher,
			encryptedData.nonce,
			'message',
			bob.keys.publicKey
		);

		// Read transport packet
		let decryptedTransportPacket = bob.readTransportPacket(
			encryptedTransportPacket
		);

		// Decrypt data
		let decryptedData = bob.decrypt(
			decryptedTransportPacket.box.data,
			bobSharedKeys.receiveKey,
			decryptedTransportPacket.box.nonce
		);

		// compare decrypted data to test object
		expect(decryptedData).toMatchObject(testObj);
	});
});
