import { Prism } from '../src/Prism';

describe('Key exchange.', () => {
	let alice: Prism;
	let bob: Prism;

	beforeEach(() => {
		alice = new Prism();
		alice.generateKeyPair();

		bob = new Prism();
		bob.generateKeyPair();
	});

	afterEach(() => {});

	test('Alice initiates initial communication and bob verifies.', () => {
		let initialCommunicationPacket = {
			sender: alice.publicKey,
			type: 'prismke1',
			data: {
				recipient: alice.sign(bob.publicKey),
			},
		};

		let initialCommunication = alice.writeMessage(
			bob.publicKey,
			initialCommunicationPacket
		);

		let receivedCommunication = bob.readMessage(initialCommunication);

		expect(receivedCommunication).toEqual(initialCommunicationPacket);

		let verifyData = bob.verify(
			bob.publicKey,
			receivedCommunication.data.recipient,
			receivedCommunication.sender
		);

		expect(verifyData).toEqual(true);
	});

	test('Bob responds to initial communication and alice verifies.', () => {
		let generatedSymmetricKey = bob.generateKey();

		let responseCommunicationPacket = {
			sender: bob.publicKey,
			type: 'prismke2',
			data: {
				recipient: bob.sign(alice.publicKey),
				key: generatedSymmetricKey,
			},
		};

		let responseCommunication = bob.writeMessage(
			alice.publicKey,
			responseCommunicationPacket
		);

		let receivedCommunication = alice.readMessage(responseCommunication);

		expect(receivedCommunication).toEqual(responseCommunicationPacket);

		let verifyData = alice.verify(
			alice.publicKey,
			receivedCommunication.data.recipient,
			receivedCommunication.sender
		);

		expect(verifyData).toEqual(true);

		expect(receivedCommunication.data.key).toEqual(generatedSymmetricKey);
	});

	test('Alice sends bob first official message and bob reads it.', () => {
		let symmetricKey = alice.generateKey();

		let messageObject = {
			sender: alice.publicKey,
			type: 'message',
			data: alice.encrypt(
				{
					message: 'Hello World!',
				},
				symmetricKey
			),
		};

		let sentMessage = alice.writeMessage(bob.publicKey, messageObject);
		let receivedMessage = bob.readMessage(sentMessage);

		expect(receivedMessage).toEqual(messageObject);

		let decryptedMessage = bob.decrypt(receivedMessage.data, symmetricKey);

		expect(decryptedMessage).toEqual({
			message: 'Hello World!',
		});
	});
});
