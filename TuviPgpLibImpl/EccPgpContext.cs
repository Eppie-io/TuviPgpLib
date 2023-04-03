///////////////////////////////////////////////////////////////////////////////
//   Copyright 2023 Eppie (https://eppie.io)
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
using MimeKit.Cryptography;
using MimeKit;
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
        private readonly DateTime KeyCreationTime = new DateTime(1970, 1, 1);
        public const long ExpirationTime = 0;

        enum KeyCreationReason : int
        {
            Signature = 0,
            Encryption = 1
        };

        enum KeyType : uint
        {
            MasterKey = 0,
            SignatureKey = 1,
            EncryptionKey = 2
        };

        protected EccPgpContext(IKeyStorage storage)
            : base(storage)
        {
        }

        /// <summary>
        /// Realization of IEllipticCurveCryptographyPgpContext interface. 
        /// Creates keypairs and add (import) it to the current context.
        /// </summary>
        /// <param name="masterKey">Master key.</param>
        /// <param name="userIdentity">User Id (email).</param>
        public void DeriveKeyPair(MasterKey masterKey, string userIdentity)
        {
            if (masterKey == null)
            {
                throw new ArgumentNullException(nameof(masterKey), "Parameter is not set.");
            }

            if (userIdentity == null)
            {
                throw new ArgumentNullException(nameof(userIdentity), "Parameter is not set.");
            }

            var generator = CreateEllipticCurveKeyRingGenerator(masterKey, userIdentity);

            Import(generator.GenerateSecretKeyRing());
            Import(generator.GeneratePublicKeyRing());
        }

        /// <summary>
        /// Creates child keypair from choosen derivationKey with specific keyIndex.
        /// </summary>
        /// <param name="derivationKey">Derivation key.</param>
        /// <param name="keyIndex">Key index.</param>
        /// <returns>Derived key pair.</returns>
        public static AsymmetricCipherKeyPair DeriveKeyPair(PrivateDerivationKey derivationKey, int keyIndex)
        {
            const string algorithm = "EC";

            byte[] childKey = DerivationKeyFactory.DerivePrivateChildKey(derivationKey, keyIndex);

            // curveOid - Curve object identifier
            DerObjectIdentifier curveOid = ECNamedCurveTable.GetOid(BitcoinEllipticCurveName);
            ECKeyGenerationParameters keyParams = new ECKeyGenerationParameters(curveOid, new SecureRandom());

            ECPrivateKeyParameters privateKey = new ECPrivateKeyParameters(algorithm, new BigInteger(1, childKey), keyParams.PublicKeyParamSet);

            ECMultiplier multiplier = new FixedPointCombMultiplier();
            ECPoint q = multiplier.Multiply(keyParams.DomainParameters.G, privateKey.D);
            ECPublicKeyParameters publicKey = new ECPublicKeyParameters(algorithm, q, keyParams.PublicKeyParamSet);

            return new AsymmetricCipherKeyPair(publicKey, privateKey);
        }

        private PgpKeyRingGenerator CreateEllipticCurveKeyRingGenerator(MasterKey masterKey, string userIdentity)
        {
            int keyIndex = 0;
            string password = string.Empty;

            PrivateDerivationKey accountKey = DerivationKeyFactory.CreatePrivateDerivationKey(masterKey, userIdentity);
            AsymmetricCipherKeyPair masterKeyPair = DeriveKeyPair(accountKey, keyIndex);
            PgpKeyPair pgpMasterKeyPair = new PgpKeyPair(PublicKeyAlgorithmTag.ECDsa, masterKeyPair, KeyCreationTime);
            PgpSignatureSubpacketGenerator certificationSubpacketGenerator = CreateSubpacketGenerator(KeyType.MasterKey, ExpirationTime);

            PrivateDerivationKey encAccountKey = DerivationKeyFactory.CreatePrivateDerivationKey(accountKey, KeyCreationReason.Encryption.ToString());
            AsymmetricCipherKeyPair encSubKeyPair = DeriveKeyPair(encAccountKey, keyIndex);
            PgpKeyPair encPgpSubKeyPair = new PgpKeyPair(PublicKeyAlgorithmTag.ECDH, encSubKeyPair, KeyCreationTime);
            PgpSignatureSubpacketGenerator encSubpacketGenerator = CreateSubpacketGenerator(KeyType.EncryptionKey, ExpirationTime);
            
            PrivateDerivationKey signAccountKey = DerivationKeyFactory.CreatePrivateDerivationKey(accountKey, KeyCreationReason.Encryption.ToString());
            AsymmetricCipherKeyPair signSubKeyPair = DeriveKeyPair(signAccountKey, keyIndex);
            PgpKeyPair signPgpSubKeyPair = new PgpKeyPair(PublicKeyAlgorithmTag.ECDsa, signSubKeyPair, KeyCreationTime);
            PgpSignatureSubpacketGenerator signSubpacketGenerator = CreateSubpacketGenerator(KeyType.SignatureKey, ExpirationTime);

            
            PgpKeyRingGenerator keyRingGenerator = new PgpKeyRingGenerator(
                certificationLevel: PgpSignature.PositiveCertification,
                masterKey: pgpMasterKeyPair,
                id: userIdentity,
                encAlgorithm: SymmetricKeyAlgorithmTag.Aes128,
                rawPassPhrase: Encoding.UTF8.GetBytes(password),
                useSha1: true,
                hashedPackets: certificationSubpacketGenerator.Generate(),
                unhashedPackets: null,
                rand: new SecureRandom());

            keyRingGenerator.AddSubKey(
                keyPair: encPgpSubKeyPair,
                hashedPackets: encSubpacketGenerator.Generate(),
                unhashedPackets: null);

            keyRingGenerator.AddSubKey(
                keyPair: signPgpSubKeyPair,
                hashedPackets: signSubpacketGenerator.Generate(),
                unhashedPackets: null);

            return keyRingGenerator;
        }

        private PgpSignatureSubpacketGenerator CreateSubpacketGenerator(KeyType type, long expirationTime)
        {
            var subpacketGenerator = new PgpSignatureSubpacketGenerator();

            switch (type)
            {
                case KeyType.MasterKey:
                    subpacketGenerator.SetKeyFlags(false, PgpKeyFlags.CanCertify);
                    break;
                case KeyType.SignatureKey:
                    subpacketGenerator.SetKeyFlags(false, PgpKeyFlags.CanSign);
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

        /// <summary>
        /// Return signing (not master) key of choosen mailbox
        /// </summary>
        /// <param name="mailbox">Mailbox.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Signing key.</returns>
        public override PgpSecretKey GetSigningKey(MailboxAddress mailbox, CancellationToken cancellationToken = default(CancellationToken))
        {
            if (mailbox == null)
            {
                throw new ArgumentNullException(nameof(mailbox));
            }

            foreach (PgpSecretKeyRing item in EnumerateSecretKeyRings(mailbox))
            {
                foreach (PgpSecretKey secretKey in item.GetSecretKeys())
                {
                    if (IsSigningNotMaster(secretKey))
                    {
                        return secretKey;
                    }
                }
            }

            throw new PrivateKeyNotFoundException(mailbox, "The private key could not be found.");
        }

        public override bool CanSign(MailboxAddress signer, CancellationToken cancellationToken = default(CancellationToken))
        {
            if (signer == null)
            {
                throw new ArgumentNullException(nameof(signer));
            }

            foreach (PgpSecretKey item in EnumerateSecretKeys(signer))
            {
                if (IsSigningNotMaster(item))
                {
                    return true;
                }
            }

            return false;
        }

        private static bool IsSigningNotMaster (PgpSecretKey key)
        {
            if (key.IsSigningKey && !key.IsMasterKey)
            {
                PgpPublicKey publicKey = key.PublicKey;
                if (!publicKey.IsRevoked() && !OpenPgpContext.IsExpired(publicKey))
                {
                    return true;
                }
            }

            return false;
        }
    }
}
