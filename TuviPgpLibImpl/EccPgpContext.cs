///////////////////////////////////////////////////////////////////////////////
//   Copyright 2025 Eppie (https://eppie.io)
//
//   Licensed under the Apache License, Version 2.0(the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.
///////////////////////////////////////////////////////////////////////////////

using KeyDerivation.Keys;
using KeyDerivationLib;
using MimeKit;
using MimeKit.Cryptography;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Math.EC.Multiplier;
using Org.BouncyCastle.Security;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using TuviPgpLib;

namespace TuviPgpLibImpl
{
    /// <summary>
    /// Elliptic Curve Cryptography PGP keys derivation extension.
    /// </summary>
    public abstract class EccPgpContext : ExternalStorageBasedPgpContext, IEllipticCurveCryptographyPgpContext
    {
        public const string BitcoinEllipticCurveName = "secp256k1";

        private static readonly DateTime KeyCreationTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
        private const long ExpirationTime = 0;
        private const SymmetricKeyAlgorithmTag DefaultSymmetricKeyAlgorithmTag = SymmetricKeyAlgorithmTag.Aes128;
        private const HashAlgorithmTag DefaultHashAlgorithmTag = HashAlgorithmTag.Sha256;

        private const string EncryptionTag = "Encryption";
        
        enum KeyType : uint
        {
            MasterKey = 0,
            EncryptionKey = 1
        };

        private const EncryptionAlgorithm DefaultEncryptionAlgorithmTag = EncryptionAlgorithm.Aes256;

        protected EccPgpContext(IKeyStorage storage)
            : base(storage)
        {
            DefaultEncryptionAlgorithm = DefaultEncryptionAlgorithmTag;
        }

        /// <summary>
        /// Derives a PGP key pair based on the provided master key and tag, associating it with the specified user identity.
        /// Generates a master key and subkey for encryption using elliptic curve cryptography (ECC) on the secp256k1 curve.
        /// The generated keys are imported into the current context.
        /// </summary>
        /// <param name="masterKey">The master key used for key derivation. Must not be null.</param>
        /// <param name="userIdentity">The user identity (e.g., email address) associated with the keys in the PGP key ring. Not used in key derivation. Must not be null.</param>
        /// <param name="tag">The string tag used to customize key derivation. Must not be null.</param>
        /// <exception cref="ArgumentNullException">Thrown if any parameter is null.</exception>
        /// <remarks>
        /// This method deterministically derives a master key, along with an encryption subkey, all from a single derivation key,
        /// using a tag-based key derivation scheme. These keys form a unified PGP key hierarchy.
        /// The <paramref name="userIdentity"/> parameter is used solely to assign the identity in the PGP key ring and does not influence key derivation.
        /// Key derivation is performed using the secp256k1 elliptic curve.
        /// </remarks>
        public void GeneratePgpKeysByTag(MasterKey masterKey, string userIdentity, string tag)
        {
            if (masterKey == null)
            {
                throw new ArgumentNullException(nameof(masterKey), "Parameter is not set.");
            }

            if (userIdentity == null)
            {
                throw new ArgumentNullException(nameof(userIdentity), "Parameter is not set.");
            }

            if (tag == null)
            {
                throw new ArgumentNullException(nameof(tag), "Parameter is not set.");
            }

            var generator = CreateEllipticCurveKeyRingGeneratorForTag(masterKey, userIdentity, tag);

            Import(generator.GenerateSecretKeyRing());
            Import(generator.GeneratePublicKeyRing());
        }

        /// <summary>
        /// Derives a PGP key pair using BIP44 hierarchical deterministic key derivation and associates it with the user identity.
        /// Generates ECC keys (secp256k1) for a master key and encryption subkey using the path m/44'/coin'/account'/channel/index.
        /// Imports the keys into the PGP key ring.
        /// </summary>
        /// <param name="masterKey">The master key for BIP44 derivation.</param>
        /// <param name="userIdentity">The user identity (e.g., email) associated with the PGP key ring, not used in derivation.</param>
        /// <param name="coin">Hardened coin type (SLIP-44) for derivation. Must be non-negative.</param>
        /// <param name="account">Hardened account index for derivation. Must be non-negative.</param>        
        /// <param name="channel">Non-hardened channel type (e.g., 10 for mail). Must be non-negative.</param>
        /// <param name="index">Non-hardened address index. Must be non-negative.</param>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="masterKey"/> or <paramref name="userIdentity"/> is null.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="account"/>, <paramref name="channel"/>, or <paramref name="index"/> is negative.</exception>
        // <remarks>
        /// This method deterministically derives a master key, along with an encryption subkey, all from a single derivation key,
        /// using a BIP44 key derivation scheme. These keys form a unified PGP key hierarchy.
        /// The derivation path follows BIP44: m/44'/coin'/account'/channel/index. 
        /// The <paramref name="userIdentity"/> parameter is used solely to assign the identity in the PGP key ring and does not influence key derivation.
        /// Key derivation is performed using the secp256k1 elliptic curve.
        /// </remarks>
        public void GeneratePgpKeysByBip44(MasterKey masterKey, string userIdentity, int coin, int account, int channel, int index)
        {
            if (masterKey == null)
            {
                throw new ArgumentNullException(nameof(masterKey), "Parameter is not set.");
            }

            if (userIdentity == null)
            {
                throw new ArgumentNullException(nameof(userIdentity), "Parameter is not set.");
            }

            if (account < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(account), "Account index must be non-negative.");
            }

            if (channel < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(channel), "Channel index must be non-negative.");
            }

            if (index < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(index), "Address index must be non-negative.");
            }

            var generator = CreateEllipticCurveKeyRingGeneratorForBip44(masterKey, userIdentity, coin, account, channel, index);

            Import(generator.GenerateSecretKeyRing());
            Import(generator.GeneratePublicKeyRing());
        }


        /// <summary>
        /// Derives a PGP key pair based on the provided master key and tag, associating it with the specified user identity.
        /// Generates a master key and encryption subkey using elliptic curve cryptography (ECC) on the secp256k1 curve.
        /// The generated keys are imported into the current context.
        /// </summary>
        /// <param name="masterKey">The master key used for key derivation. Must not be null.</param>
        /// <param name="userIdentity">The user identity (e.g., email address) associated with the keys in the PGP key ring. Not used in key derivation. Must not be null.</param>
        /// <param name="tag">The string tag used to customize key derivation. Must not be null.</param>
        /// <exception cref="ArgumentNullException">Thrown if any parameter is null.</exception>
        /// This method deterministically derives unique keys: a master key, along with an encryption subkey,
        /// using a tag-based key derivation scheme. These keys form a unified PGP key hierarchy.
        /// The <paramref name="userIdentity"/> parameter is used solely to assign the identity in the PGP key ring and does not influence key derivation.
        /// Key derivation is performed using the secp256k1 elliptic curve.
        /// </remarks>
        public void GeneratePgpKeysByTagOld(MasterKey masterKey, string userIdentity, string tag)
        {
            if (masterKey == null)
            {
                throw new ArgumentNullException(nameof(masterKey), "Parameter is not set.");
            }

            if (userIdentity == null)
            {
                throw new ArgumentNullException(nameof(userIdentity), "Parameter is not set.");
            }

            if (tag == null)
            {
                throw new ArgumentNullException(nameof(tag), "Parameter is not set.");
            }

            var generator = CreateEllipticCurveKeyRingGeneratorOld(masterKey, userIdentity, tag);

            Import(generator.GenerateSecretKeyRing());
            Import(generator.GeneratePublicKeyRing());
        }

        /// <summary>
        /// Generates an elliptic curve (EC) public key using BIP-44 hierarchical deterministic key derivation.
        /// </summary>
        /// <param name="masterKey">The master key used as the root for key derivation. Must not be null.</param>
        /// <param name="coin">The hardened coin type index as per SLIP-44. Must be non-negative.</param>
        /// <param name="account">The hardened account index for derivation. Must be non-negative.</param>
        /// <param name="channel">The non-hardened channel index (e.g., 10 for mail). Must be non-negative.</param>
        /// <param name="index">The non-hardened address index for derivation. Must be non-negative.</param>
        /// <returns>An <see cref="ECPublicKeyParameters"/> object representing the derived public key on the secp256k1 curve.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="masterKey"/> is null.</exception>
        /// <exception cref="ArgumentException">Thrown when the derived private key is invalid (e.g., zero or incorrect length).</exception>
        /// <remarks>
        /// This method follows the BIP-44 derivation path: <c>m/44'/coin'/account'/channel/index</c>.
        /// The resulting key is suitable for use in elliptic curve cryptography operations, such as ECDH or ECDsa.
        /// </remarks>
        public static ECPublicKeyParameters GenerateEccPublicKey(MasterKey masterKey, int coin, int account, int channel, int index)
        {
            if (masterKey == null)
            {
                throw new ArgumentNullException(nameof(masterKey));
            }

            if (coin < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(coin), "Coin index must be non-negative.");
            }

            if (account < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(account), "Account index must be non-negative.");
            }

            if (channel < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(channel), "Channel index must be non-negative.");
            }

            if (index < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(index), "Address index must be non-negative.");
            }

            using (var childKey = DerivationKeyFactory.CreatePrivateDerivationKeyBip44(masterKey, coin, account, channel, index))
            {
                return GenerateEccPublicKey(childKey);
            }
        }

        /// <summary>
        /// Generates an elliptic curve (EC) public key using a tag-based key derivation scheme.
        /// </summary>
        /// <param name="masterKey">The master key used as the root for key derivation. Must not be null.</param>
        /// <param name="keyTag">The string tag used to customize the key derivation process. Must not be null.</param>
        /// <returns>An <see cref="ECPublicKeyParameters"/> object representing the derived public key on the secp256k1 curve.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="masterKey"/> or <paramref name="keyTag"/> is null.</exception>
        /// <exception cref="ArgumentException">Thrown when the derived private key is invalid (e.g., zero or incorrect length).</exception>
        /// <remarks>
        /// This method derives a private key using the provided <paramref name="keyTag"/>, followed by an encryption-specific tag
        /// and a child key index of 0. The resulting key is suitable for use in elliptic curve cryptography operations, such as ECDH.
        /// </remarks>
        public static ECPublicKeyParameters GenerateEccPublicKey(MasterKey masterKey, string keyTag)
        {
            if (masterKey == null)
            {
                throw new ArgumentNullException(nameof(masterKey));
            }

            if (string.IsNullOrEmpty(keyTag))
            {
                throw new ArgumentException(nameof(keyTag));
            }

            using (var childKey = DerivationKeyFactory.CreatePrivateDerivationKey(masterKey, keyTag))
            {
                return GenerateEccPublicKey(childKey);
            }
        }

        /// <summary>
        /// Creates a PGP public key ring containing a master key and encryption subkey
        /// using elliptic curve cryptography parameters, associating them with a user identity.
        /// </summary>
        /// <param name="masterPublicKey">The elliptic curve public key parameters for the master key (ECDsa). Must not be null.</param>
        /// <param name="encryptionPublicKey">The elliptic curve public key parameters for the encryption subkey (ECDH). Must not be null.</param>
        /// <param name="userIdentity">The user identity (e.g., email address) to associate with the keys. Must not be null or empty.</param>
        /// <returns>A <see cref="PgpPublicKeyRing"/> object containing the master key and encryption subkey.</returns>
        /// <exception cref="ArgumentNullException">Thrown when any of the public key parameters or <paramref name="userIdentity"/> is null.</exception>
        /// <exception cref="ArgumentException">Thrown when <paramref name="userIdentity"/> is empty.</exception>
        public static PgpPublicKeyRing CreatePgpPublicKeyRing(
            ECPublicKeyParameters masterPublicKey,
            ECPublicKeyParameters encryptionPublicKey,
            string userIdentity)
        {
            if (masterPublicKey == null)
            {
                throw new ArgumentNullException(nameof(masterPublicKey));
            }

            if (encryptionPublicKey == null)
            {
                throw new ArgumentNullException(nameof(encryptionPublicKey));
            }

            if (string.IsNullOrEmpty(userIdentity))
            {
                throw new ArgumentException("User identity must not be null or empty.", nameof(userIdentity));
            }

            using (var memoryStream = new MemoryStream())
            {
                // Create master key (ECDsa)
                var masterBcpgKey = new ECDsaPublicBcpgKey(
                    oid: masterPublicKey.PublicKeyParamSet,
                    point: masterPublicKey.Q
                );

                var masterPublicPk = new PublicKeyPacket(
                    algorithm: PublicKeyAlgorithmTag.ECDsa,
                    time: KeyCreationTime,
                    key: masterBcpgKey
                );

                // Encode master key
                masterPublicPk.Encode(new BcpgOutputStream(memoryStream));

                // Add user identity
                var userIdPacket = new UserIdPacket(userIdentity);
                userIdPacket.Encode(new BcpgOutputStream(memoryStream));

                // Create encryption subkey (ECDH)
                var encryptionBcpgKey = new ECDHPublicBcpgKey(
                    oid: encryptionPublicKey.PublicKeyParamSet,
                    point: encryptionPublicKey.Q,
                    hashAlgorithm: DefaultHashAlgorithmTag,
                    symmetricKeyAlgorithm: DefaultSymmetricKeyAlgorithmTag
                );

                var encryptionPublicPk = new PublicSubkeyPacket(
                    algorithm: PublicKeyAlgorithmTag.ECDH,
                    time: KeyCreationTime,
                    key: encryptionBcpgKey
                );

                // Encode encryption subkey
                encryptionPublicPk.Encode(new BcpgOutputStream(memoryStream));

                // Reset stream position and create key ring
                memoryStream.Position = 0;
                return new PgpPublicKeyRing(memoryStream);
            }
        }

        private static ECPublicKeyParameters GenerateEccPublicKey(PrivateDerivationKey derivationKey)
        {
            var keyPair = GenerateEccKeyPairFromPrivateKey(derivationKey);
            var publicKeyPar = keyPair.Public as ECPublicKeyParameters;

            return publicKeyPar;
        }

        private static AsymmetricCipherKeyPair GenerateEccKeyPairFromPrivateKey(PrivateDerivationKey derivationKey)
        {
            if (derivationKey == null)
            {
                throw new ArgumentNullException(nameof(derivationKey));
            }

            // Scalar must be 32 bytes long
            if (derivationKey.Scalar.IsEmpty || derivationKey.Scalar.Length != 32)
            {
                throw new ArgumentException("Invalid private key scalar.", nameof(derivationKey));
            }

            const string algorithm = "EC";

            // curveOid - Curve object identifier
            DerObjectIdentifier curveOid = ECNamedCurveTable.GetOid(BitcoinEllipticCurveName);
            ECKeyGenerationParameters keyParams = new ECKeyGenerationParameters(curveOid, new SecureRandom());

            ECPrivateKeyParameters privateKey = new ECPrivateKeyParameters(algorithm, new BigInteger(1, derivationKey.Scalar.ToArray()), keyParams.PublicKeyParamSet);

            ECMultiplier multiplier = new FixedPointCombMultiplier();
            ECPoint q = multiplier.Multiply(keyParams.DomainParameters.G, privateKey.D);
            ECPublicKeyParameters publicKey = new ECPublicKeyParameters(algorithm, q, keyParams.PublicKeyParamSet);

            return new AsymmetricCipherKeyPair(publicKey, privateKey);
        }

        private PgpKeyRingGenerator CreateEllipticCurveKeyRingGeneratorOld(MasterKey masterKey, string userIdentity, string tag)
        {
            const int KeyIndex = 0;
            const string SignatureTag = "Signature";
            string password = string.Empty;

            using (var accountKey = DerivationKeyFactory.CreatePrivateDerivationKey(masterKey, tag))
            using (var accountChildKey = DerivationKeyFactory.DerivePrivateChildKey(accountKey, KeyIndex))
            {
                using (var encAccountKey = DerivationKeyFactory.CreatePrivateDerivationKey(accountKey, EncryptionTag))
                using (var encAccountChildKey = DerivationKeyFactory.DerivePrivateChildKey(encAccountKey, KeyIndex))
                {
                    AsymmetricCipherKeyPair encSubKeyPair = GenerateEccKeyPairFromPrivateKey(encAccountChildKey);
                    PgpKeyPair encPgpSubKeyPair = CreatePgpSubkey(PublicKeyAlgorithmTag.ECDH, encSubKeyPair, KeyCreationTime);
                    PgpSignatureSubpacketGenerator encSubpacketGenerator = CreateSubpacketGenerator(KeyType.EncryptionKey, ExpirationTime);

                    using (var masterAccountKey = DerivationKeyFactory.CreatePrivateDerivationKey(accountKey, SignatureTag))
                    using (var masterAccountChildKey = DerivationKeyFactory.DerivePrivateChildKey(masterAccountKey, KeyIndex))
                    {
                        AsymmetricCipherKeyPair masterKeyPair = GenerateEccKeyPairFromPrivateKey(masterAccountChildKey);
                        PgpKeyPair pgpMasterKeyPair = new PgpKeyPair(PublicKeyAlgorithmTag.ECDsa, masterKeyPair, KeyCreationTime);
                        PgpSignatureSubpacketGenerator certificationSubpacketGenerator = CreateSubpacketGenerator(KeyType.MasterKey, ExpirationTime);

                        return CreatePgpKeyRingGenerator(userIdentity, password, pgpMasterKeyPair, certificationSubpacketGenerator, encPgpSubKeyPair, encSubpacketGenerator);
                    }
                }
            }
        }

        private PgpKeyRingGenerator CreateEllipticCurveKeyRingGeneratorForTag(MasterKey masterKey, string userIdentity, string tag)
        {
            using (var tagKey = DerivationKeyFactory.CreatePrivateDerivationKey(masterKey, tag))
            {
                return CreatePgpKeyRingGenerator(userIdentity, tagKey);
            }
        }

        private PgpKeyRingGenerator CreateEllipticCurveKeyRingGeneratorForBip44(
            MasterKey masterKey,
            string userIdentity,
            int coin,
            int account,
            int channel,
            int index)
        {
            using (var bip44Key = DerivationKeyFactory.CreatePrivateDerivationKeyBip44(masterKey, coin, account, channel, index))
            {
                return CreatePgpKeyRingGenerator(userIdentity, bip44Key);
            }
        }

        private PgpKeyRingGenerator CreatePgpKeyRingGenerator(string userIdentity, PrivateDerivationKey derivationKey)
        {
            string password = string.Empty;

            AsymmetricCipherKeyPair masterKeyPair = GenerateEccKeyPairFromPrivateKey(derivationKey);

            PgpKeyPair pgpMasterKeyPair = new PgpKeyPair(PublicKeyAlgorithmTag.ECDsa, masterKeyPair, KeyCreationTime);
            PgpSignatureSubpacketGenerator certificationSubpacketGenerator = CreateSubpacketGenerator(KeyType.MasterKey, ExpirationTime);

            PgpKeyPair encPgpSubKeyPair = CreatePgpSubkey(PublicKeyAlgorithmTag.ECDH, masterKeyPair, KeyCreationTime);
            PgpSignatureSubpacketGenerator encSubpacketGenerator = CreateSubpacketGenerator(KeyType.EncryptionKey, ExpirationTime);

            return CreatePgpKeyRingGenerator(userIdentity, password, pgpMasterKeyPair, certificationSubpacketGenerator, encPgpSubKeyPair, encSubpacketGenerator);
        }

        private static PgpKeyRingGenerator CreatePgpKeyRingGenerator(
            string userIdentity, 
            string password, 
            PgpKeyPair pgpMasterKeyPair, 
            PgpSignatureSubpacketGenerator certificationSubpacketGenerator, 
            PgpKeyPair encPgpSubKeyPair, 
            PgpSignatureSubpacketGenerator encSubpacketGenerator)
        {
            PgpKeyRingGenerator keyRingGenerator = new PgpKeyRingGenerator(
                certificationLevel: PgpSignature.PositiveCertification,
                masterKey: pgpMasterKeyPair,
                id: userIdentity,
                encAlgorithm: DefaultSymmetricKeyAlgorithmTag,
                rawPassPhrase: Encoding.UTF8.GetBytes(password),
                useSha1: true,
                hashedPackets: certificationSubpacketGenerator.Generate(),
                unhashedPackets: null,
                rand: new SecureRandom());

            keyRingGenerator.AddSubKey(
                keyPair: encPgpSubKeyPair,
                hashedPackets: encSubpacketGenerator.Generate(),
                unhashedPackets: null);

            return keyRingGenerator;
        }

        private static PgpKeyPair CreatePgpSubkey(PublicKeyAlgorithmTag algorithm, AsymmetricCipherKeyPair keyPair, DateTime time)
        {
            IBcpgKey bcpgKey;
            if (keyPair.Public is ECPublicKeyParameters ecK)
            {
                if (algorithm == PublicKeyAlgorithmTag.ECDH)
                {
                    bcpgKey = new ECDHPublicBcpgKey(ecK.PublicKeyParamSet, ecK.Q, DefaultHashAlgorithmTag,
                        DefaultSymmetricKeyAlgorithmTag);
                }
                else if (algorithm == PublicKeyAlgorithmTag.ECDsa)
                {
                    bcpgKey = new ECDsaPublicBcpgKey(ecK.PublicKeyParamSet, ecK.Q);
                }
                else
                {
                    throw new PgpException("unsupported EC algorithm");
                }
            }
            else
            {
                throw new PgpException("unsupported algorithm");
            }

            PublicKeyPacket publicPk = new PublicSubkeyPacket(algorithm, time, bcpgKey);

            var pub = new PgpPublicKey(publicPk);
            var priv = new PgpPrivateKey(pub.KeyId, pub.PublicKeyPacket, keyPair.Private);
            return new PgpKeyPair(pub, priv);
        }

        private PgpSignatureSubpacketGenerator CreateSubpacketGenerator(KeyType type, long expirationTime)
        {
            var subpacketGenerator = new PgpSignatureSubpacketGenerator();

            switch (type)
            {
                case KeyType.MasterKey:
                    subpacketGenerator.SetKeyFlags(false, PgpKeyFlags.CanCertify | PgpKeyFlags.CanSign);
                    break;
                case KeyType.EncryptionKey:
                    subpacketGenerator.SetKeyFlags(false, PgpKeyFlags.CanEncryptCommunications | PgpKeyFlags.CanEncryptStorage);
                    break;
            }

            subpacketGenerator.SetPreferredSymmetricAlgorithms(false, this.EnabledEncryptionAlgorithms.Select(e => (int)e).ToArray());
            subpacketGenerator.SetPreferredHashAlgorithms(false, this.EnabledDigestAlgorithms.Select(e => (int)e).ToArray());

            if (expirationTime > 0)
            {
                subpacketGenerator.SetKeyExpirationTime(false, expirationTime);
                subpacketGenerator.SetSignatureExpirationTime(false, expirationTime);
            }

            subpacketGenerator.SetFeature(false, Org.BouncyCastle.Bcpg.Sig.Features.FEATURE_MODIFICATION_DETECTION);

            return subpacketGenerator;
        }
    }
}
