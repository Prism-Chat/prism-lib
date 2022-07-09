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
});
