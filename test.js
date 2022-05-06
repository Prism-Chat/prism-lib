const { Prism } = require('./dist/Prism-min.js');
const Crypto = require('crypto');

//console.log(Crypto.randomBytes(2048).toString('base64'));

const prism = new Prism();
prism.generateKeyPair();
console.log('Prism keys initialized!');
console.log('===========================');

const testSymmetricEncryption = () => {
	let symKey = prism.generateKey();
	let testObj = {
		message: 'test',
	};
	let encrypted = prism.encrypt(testObj, symKey);
	let decrypted = prism.decrypt(encrypted, symKey);

	console.log(
		'testSymmetricEncryption: ' +
			(JSON.stringify(testObj) === JSON.stringify(decrypted))
	);
};

const testRsaPublicEncrypt = () => {
	let testObj = {
		message: 'test',
	};
	let encrypted = prism.publicEncrypt(testObj);
	let decrypted = prism.privateDecrypt(encrypted);

	console.log(
		'testRsaPublicEncrypt: ' +
			(JSON.stringify(testObj) === JSON.stringify(decrypted))
	);
};

const testRsaSign = () => {
	let testObj = {
		message: 'test',
	};

	let signed = prism.sign(testObj);
	let verified = prism.verify(testObj, signed);

	console.log('testRsaSign: ' + verified);
};

testSymmetricEncryption();
testRsaPublicEncrypt();
testRsaSign();

console.log('===========================');

const alice = new Prism();
alice.generateKeyPair();
console.log('Alice keys initialized!');

const bob = new Prism();
bob.generateKeyPair();
console.log('Bob keys initialized!');

console.log('===========================');

const aliceCreatesInitialPacket = () => {
	let packet = {
		identity: alice.publicKey,
		recipient: alice.sign(bob.publicKey),
	};

	console.log('aliceCreatesInitialPacket: ' + true);

	return packet;
};

const bobVerifiesInitialPacket = (initialPacket) => {
	let verified = bob.verify(
		bob.publicKey,
		initialPacket.recipient,
		initialPacket.identity
	);
	console.log('bobVerifiesInitialPacket: ' + verified);
};

let bobSymKey = null;

const bobCreatesSymmetricKey = (initialPacket) => {
	bobSymKey = bob.generateKey();

	let packet = {
		identity: bob.publicKey,
		recipient: bob.sign(initialPacket.identity),
		key: bob.publicEncrypt(bobSymKey, initialPacket.identity),
	};

	console.log('bobCreatesSymmetricKey: ' + true);

	return packet;
};

let aliceSymKey = null;

const aliceProcessResponsePacket = (responsePacket) => {
	alice.verify(
		alice.publicKey,
		responsePacket.recipient,
		responsePacket.identity
	);

	aliceSymKey = alice.privateDecrypt(responsePacket.key);

	console.log('aliceProcessResponsePacket: ' + true);
};

let initialPacket = aliceCreatesInitialPacket();
bobVerifiesInitialPacket(initialPacket);
let responsePacket = bobCreatesSymmetricKey(initialPacket);
aliceProcessResponsePacket(responsePacket);

console.log('Verify symmetric keys: ' + (bobSymKey == aliceSymKey));

console.log('===========================');

let dataObject = {
	type: 'message',
	data: {
		message: 'Hello World!',
	},
};

const testAliceWriteMessageToBob = () => {
	let messageToBob = alice.writeMessage(bob.publicKey, dataObject);

	console.log('testAliceWriteMessageToBob: ' + true);

	return messageToBob;
};

let messageToBob = testAliceWriteMessageToBob();

const testBobReadMessageFromAlice = (packet) => {
	let messageFromAlice = bob.readMessage(packet);

	console.log('testBobReadMessageFromAlice: ' + true);
	return messageFromAlice;
};

let decryptedMessage = testBobReadMessageFromAlice(messageToBob);

console.log(
	'Verify message encryption: ' +
		(JSON.stringify(dataObject) == JSON.stringify(decryptedMessage))
);
