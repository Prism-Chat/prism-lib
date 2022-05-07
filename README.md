# Prism Lib

This is the main client library used to encrypt information on the client side before even being sent to the server.

To use this library you can either include the Prism TypeScript file in a typescript project, or you can build a JavaScript version of the library.

## How to use

This is a small guide on how to use the Prism client library as well as the available functions.

### Create Prism Instance

When you create a Prism object it takes two optional parameters of an rsa public key and an rsa private key. Both key are required to run most of the other Prism functions. If you do not have an RSA key-pair to pass into the constructor you can leave is blank and generate two new keys with another function.

``` JavaScript
const Prism = new Prism(publicKey, privateKey);
```

### Generate Key Pair

Creates a new RSA key-pair returning an object containing both keys as well as assigning both new keys to the state of the Prism object.

``` JavaScript
const {publicKey, privateKey} = Prism.generateKeyPair();
```

### Generate Key

Creates a new and random key designed to be used for symmetric encryption.

``` JavaScript
const key = Prism.generateKey();
```

### Public Key Encrypt

This function takes a JavaScript object and a public key. It then coverts the JavaScript object into an encrypted string.

``` JavaScript
const encryptedString = Prism.publicEncrypt(data, publicKey?);
```

### Private Key Decrypt

This function takes in a string that has been encrypted with the ```publicEncrypt``` function and then attempts to decrypt the string with your private key.

``` JavaScript
const decryptedObject = Prism.privateDecrypt(data);
```

### Sign

This function allows you to create a signature of a JavaScript object with your private key.

``` JavaScript
const signedString = Prism.sign(data);
```

### Verify

This function is used to verify that a know piece of data was signed with the private key of a corresponding public key.

``` JavaScript
const verifiedString = Prism.verify(knownData, signatureString, publicKey);
```

### Encrypt

This function allows you to encrypt a JavaScript object symmetrically by using a key.

``` JavaScript
const encryptedString = Prism.encrypt(data, key);
```

### Decrypt

This function takes in a string that was encrypted with the ```encrypt``` function and the same symmetric key and returns a JavaScript object containing the unencrypted data.

``` JavaScript
const decryptedString = Prism.decrypt(data, key);
```

### To Pem File

This function takes in the raw form of an RSA key, and a string indicating weather it is a private or public key and transforms it into pem format.

``` JavaScript
const pemKey = Prism.toPem(key, type);
```

### Write Message

This function helps users create a stand prism format message. It takes in the public key of the recipient of the message and the data itself. It then generates a symmetric key and encrypts the data with the symmetric key, and then encrypts the symmetric key itself with the recipients public key. Since this packet contains both an encrypted version of the key and the data itself, both pieces of data will be separated by a colin.

``` JavaScript
const encryptedMessage = Prism.writeMessage(recipientPublicKey, prismDataObject);
```

### Read Message

This function parses the data that is in the write message format and returns a JavaScript object containing the decrypted data.

``` JavaScript
const decryptedMessage = Prism.readMessage(packet);
```
