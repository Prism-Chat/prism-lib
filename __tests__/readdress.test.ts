import { Prism } from '../src/Prism';

describe('Readdress.', () => {
	let alice: Prism;
	let bob: Prism;

	beforeEach(() => {
		alice = new Prism();
		alice.generateKeyPair();

		bob = new Prism();
		bob.generateKeyPair();
	});

	afterEach(() => {});

	test('Alice sends bob a readdress packet.', () => {
		let symmetricKey = alice.generateKey();

		let aliceOldPublicKey = alice.publicKey;
		alice.generateKeyPair();

		let messageObject = {
			sender: alice.publicKey,
			type: 'readdress',
			data: alice.encrypt(
				{
					publicKey: alice.publicKey,
					recipient: alice.sign(bob.publicKey),
				},
				symmetricKey
			),
		};

		let sentMessage = alice.writeMessage(bob.publicKey, messageObject);
		let receivedMessage = bob.readMessage(sentMessage);

		expect(receivedMessage).toEqual(messageObject);
		expect(receivedMessage.type).toEqual('readdress');

		let decryptedMessage = bob.decrypt(receivedMessage.data, symmetricKey);

		let verifyData = bob.verify(
			bob.publicKey,
			decryptedMessage.recipient,
			decryptedMessage.publicKey
		);

		expect(verifyData).toEqual(true);
		expect(decryptedMessage.publicKey).not.toEqual(aliceOldPublicKey);
	});
});
