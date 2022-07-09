# Prism Lib

The Prism library gives you easy to use tools built upon [libsodium](https://libsodium.gitbook.io/doc/) to perform E2E encryption from the client side!

To use this library you can either include the Prism TypeScript file in a typescript project, or you can build the pure JavaScript version of the library.

## How to use

This is a small guide on how to use the Prism client library as well as the available functions.

### Create Prism Instance

The Prism object is designed to represent a client, in this case we will be using Alice and Bob as examples. Once you create a prism object you must then run the init function which is an async function. The init function allows you to put existing keys into the object state, or if none are provided it will generate a new set of keys. This must be done due to the use of libsodium.

``` JavaScript
const alice = new Prism();
alice.init();
```

### Generate Key Pair

Creates a new RSA key-pair returning an object containing both keys as well as assigning both new keys to the state of the Prism object.

``` JavaScript
const {publicKey, privateKey} = Prism.generateKeyPair();
```

### Read keys

You can read the keys in an object using the ```keys``` getter.

``` JavaScript
const keys = alice.keys;
```

### Generate symmetric key

You can generate a random key to be used in symmetric encryption.

``` JavaScript
const key = alice.generateKey();
```

### Encrypt data symmetrically

In order to encrypt data symmetrically you can use the following function. It also exports the randomly generated nonce along with the cypher test.

``` JavaScript
const encrypted = alice.encrypt(data: object, key: string);
```

### Decrypt data symmetrically

This function allows you to decrypt data that has been symmetrically encrypted with the public nonce and key.

``` JavaScript
const decrypted = alice.decrypt(data: string, key: string, publicNonce: string);
```

### Encrypt data with public key

If you know the public key of a recipient you can encrypt data to send to them.

``` JavaScript
const var = alice.encryptPublic(data: any, recipientPublicKey: string);
```

### Decrypt data with private key

If someone sends you data encrypted with your public key, you can decrypt it using your private key.

``` JavaScript
const var = alice.decryptPrivate(data: string);
```

### Sign and encrypt data (Box)

A Box is a standard encryption scheme that involves signing data with your private key and then encrypting both the data and signature with the recipients public key.

``` JavaScript
const var = alice.encryptBox(data: any, recipientPublicKey: string);
```

### Decrypt and verify data (Box)

If data has been encrypted with a Box you can then decrypt and verify it by providing the cypher text, public nonce and the senders public key.

``` JavaScript
const var = alice.decryptBox(data: string, nonce: number, senderPublicKey: string);
```

### Create a key pair to be used in a key exchange

When establishing a shared key you first need to generate a compatible key pair. This function will return both a public and private key.

``` JavaScript
const var = alice.generateKeyExchangePair();
```

### Calculate shared key set as IC

When you trade public keys pairs intended to be used for key exchange this function allows you to generate a set of new shared keys. This function is intended to be used by the person how made the initial communication, as there is a slightly different function that must be used by the other participant. This function will return two keys intended to be used for symmetric encryption and one used for sending and one for receiving. The other participant will mathematically produce the same keys intended for the opposite purposes.

``` JavaScript
const var = alice.keyExchangeIC();
```

### Calculate shared key set as RC

When you trade public keys pairs intended to be used for key exchange this function allows you to generate a set of new shared keys. This function is intended to be used by the person how made the response communication, as there is a slightly different function that must be used by the other participant. This function will return two keys intended to be used for symmetric encryption and one used for sending and one for receiving. The other participant will mathematically produce the same keys intended for the opposite purposes.

``` JavaScript
const var = alice.keyExchangeRC();
```

### Derive new key from previous

This function will allow you to alter your keys upon each message without any communication from the opposite participant. This function is intended to be used to morph the send and receive keys generated after the key exchange.

``` JavaScript
const var = alice.keyDerivation();
```
