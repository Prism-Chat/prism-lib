import { Prism } from '../src/Prism';

describe('Unit testing.', () => {
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

	test('Test public encrypt and decrypt.', () => {
		const testObj = {
			message: 'Hello World!',
		};

		let cypher = alice.encryptPublic(testObj, bob.keys.publicKey);
		let decrypted = bob.decryptPrivate(cypher);

		expect(decrypted).toMatchObject(testObj);
	});

	test('Test box encrypt and decrypt.', () => {
		const testObj = {
			message: 'Hello World!',
		};

		let { nonce, cypher } = alice.encryptBox(testObj, bob.keys.publicKey);
		let decrypted = bob.decryptBox(cypher, nonce, alice.keys.publicKey);

		expect(decrypted).toMatchObject(testObj);
	});

	test('Test key exchange.', () => {
		let aliceSessionPair = alice.generateKeyExchangePair();
		let bobSessionPair = alice.generateKeyExchangePair();

		let aliceSharedKeys = alice.keyExchangeIC(
			aliceSessionPair.publicKey,
			aliceSessionPair.privateKey,
			bobSessionPair.publicKey
		);
		let bobSharedKeys = bob.keyExchangeRC(
			bobSessionPair.publicKey,
			bobSessionPair.privateKey,
			aliceSessionPair.publicKey
		);

		expect(aliceSharedKeys.sendKey).toBe(bobSharedKeys.receiveKey);
		expect(bobSharedKeys.sendKey).toBe(aliceSharedKeys.receiveKey);
	});

	test('Test key exchange and derivation.', () => {
		let aliceSessionPair = alice.generateKeyExchangePair();
		let bobSessionPair = alice.generateKeyExchangePair();

		let aliceSharedKeys = alice.keyExchangeIC(
			aliceSessionPair.publicKey,
			aliceSessionPair.privateKey,
			bobSessionPair.publicKey
		);

		let bobSharedKeys = bob.keyExchangeRC(
			bobSessionPair.publicKey,
			bobSessionPair.privateKey,
			aliceSessionPair.publicKey
		);

		let kdfAliceSendKey = alice.keyDerivation(aliceSharedKeys.sendKey);
		let kdfAliceReceiveKey = alice.keyDerivation(aliceSharedKeys.receiveKey);
		let kdfBobSendKey = bob.keyDerivation(bobSharedKeys.sendKey);
		let kdfBobReceiveKey = bob.keyDerivation(bobSharedKeys.receiveKey);

		expect(aliceSharedKeys.sendKey).toBe(bobSharedKeys.receiveKey);
		expect(bobSharedKeys.sendKey).toBe(aliceSharedKeys.receiveKey);

		expect(kdfAliceSendKey).toBe(kdfBobReceiveKey);
		expect(kdfBobSendKey).toBe(kdfAliceReceiveKey);
	});

	test('Test symmetric encryption.', () => {
		const testObj = {
			message: 'Hello World!',
		};

		let key = alice.generateKey();
		let cypher = alice.encrypt(testObj, key);
		let decrypted = bob.decrypt(cypher.cypher, key, cypher.publicNonce);

		expect(decrypted).toMatchObject(testObj);
	});
});
