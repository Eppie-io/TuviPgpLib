# TuviPgpLib
TuviPgpLib is a [PGP](https://en.wikipedia.org/wiki/Pretty_Good_Privacy) (Pretty Good Privacy) library that provides encryption, signing, import/export, and key management functionality. It uses [BouncyCastle](https://www.bouncycastle.org/) for cryptographic operations, providing secure encryption and signing of email and other data.

## Features

1. **Key Management**
    - Key Import/Export: Both public and private key import and export are supported. Both ASCII Armored and binary key export are supported.
    - External Storage Support: The IKeyStorage interface allows the library to integrate with external key storage to save and load key data.
    - Public and Secret Key Ring Support: The library allows importing and exporting PGP public/secret key ring bundles.

2. **Key Search and Filtering**
    - Ability to filter and match keys with email addresses via the IKeyMatcher interface.
    - Automatic key selection for encryption and signing based on email address is supported.

3. **Data Encryption and Signing**
    - Support for data and message encryption using PGP, as well as digital signature generation.
    - Signature verification and message decryption with data integrity checking.

4. **Exception Handling**
    - Special exceptions for working with keys, including:
      - PublicKeyNotFoundException — the key was not found.
      - PublicKeyAlreadyExistException — the key already exists.
      - ImportPublicKeyException and others — exceptions when importing keys.
    - Handling various errors related to cryptographic algorithms and key formats.

5. **Extensibility**
    - TuviPgpContext — the main context for working with PGP, which can be extended or modified for specific implementations.
    - Ability to use various encryption algorithms and standards via the BouncyCastle library.



## Usage examples

### Importing a public key

```csharp
using (var stream = File.OpenRead("publickey.asc"))
{
  pgpContext.ImportPublicKeys(stream, isArmored: true);
}
```

### Exporting a secret key
```csharp
using (var outputStream = File.Create("privatekey.asc"))
{
pgpContext.ExportSecretKeys("user@example.com", outputStream, isArmored: true);
}
```

### Encrypting a message
```csharp
var encryptedMessage = pgpContext.Encrypt("message", recipientEmail);
```

### Signature Verification
```csharp
bool isValid = pgpContext.VerifySignature(signedMessage, senderEmail);
```


## Requirements
- .NET Standard 2.0
- BouncyCastle for cryptographic operations

## Installation
WIP


## License
The project is licensed under the Apache License 2.0. See the LICENSE file for details.


## Contributions
We welcome any contributions to the project! If you have suggestions or find a bug, create an issue or submit a pull request.
