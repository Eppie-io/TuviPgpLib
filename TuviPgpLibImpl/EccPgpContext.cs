///////////////////////////////////////////////////////////////////////////////
//   Copyright 2022 Eppie (https://eppie.io)
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
using TuviPgpLib;

namespace TuviPgpLibImpl
{
    /// <summary>
    /// Elliptic Curve Cryptography PGP keys derivation extension.
    /// </summary>
    public abstract class EccPgpContext : ExternalStorageBasedPgpContext, IEllipticCurveCryptographyPgpContext
    {
        public const string BitcoinEllipticCurveName = "secp256k1";
        public enum ChildKeyIndex : int
        {
            Signature = 0,
            Encryption = 1
        };
        private readonly DateTime KeyCreationTime = new DateTime(1970, 1, 1);
        public const long ExpirationTime = 0;

        protected EccPgpContext(IKeyStorage storage)
            : base(storage)
        {
        }

        public void DeriveKeyPair(MasterKey masterKey, string userIdentity, string password)
        {
            if (masterKey == null)
            {
                throw new ArgumentNullException(nameof(masterKey), "Parameter is not set.");
            }

            if (userIdentity == null)
            {
                throw new ArgumentNullException(nameof(userIdentity), "Parameter is not set.");
            }

            if (password == null)
            {
                throw new ArgumentNullException(nameof(password), "Parameter is not set.");
            }

            var generator = CreateEllipticCurveKeyRingGenerator(masterKey, userIdentity, password);

            Import(generator.GenerateSecretKeyRing());
            Import(generator.GeneratePublicKeyRing());
        }

        public static AsymmetricCipherKeyPair DeriveKeyPair(MasterKey masterKey, string userIdentity, int keyIndex)
        {
            const string algorithm = "EC";

            byte[] childKey = AccountKeyFactory.DeriveAccountChildKey(masterKey, userIdentity, keyIndex);

            // curveOid - Curve object identifier
            DerObjectIdentifier curveOid = ECNamedCurveTable.GetOid(BitcoinEllipticCurveName);
            ECKeyGenerationParameters keyParams = new ECKeyGenerationParameters(curveOid, new SecureRandom());

            ECPrivateKeyParameters privateKey = new ECPrivateKeyParameters(algorithm, new BigInteger(1, childKey), keyParams.PublicKeyParamSet);

            ECMultiplier multiplier = new FixedPointCombMultiplier();
            ECPoint q = multiplier.Multiply(keyParams.DomainParameters.G, privateKey.D);
            ECPublicKeyParameters publicKey = new ECPublicKeyParameters(algorithm, q, keyParams.PublicKeyParamSet);

            return new AsymmetricCipherKeyPair(publicKey, privateKey);
        }

        private PgpKeyRingGenerator CreateEllipticCurveKeyRingGenerator(MasterKey masterKey, string userIdentity, string password, SymmetricKeyAlgorithmTag algorithm = SymmetricKeyAlgorithmTag.Aes128)
        {
            AsymmetricCipherKeyPair signatureKeyPair = DeriveKeyPair(
                masterKey,
                userIdentity,
                (int)ChildKeyIndex.Signature);

            AsymmetricCipherKeyPair encryptionKeyPair = DeriveKeyPair(
                masterKey,
                userIdentity,
                (int)ChildKeyIndex.Encryption);

            PgpKeyPair signaturePgpKeyPair = new PgpKeyPair(PublicKeyAlgorithmTag.ECDsa, signatureKeyPair, KeyCreationTime);
            PgpKeyPair encryptionPgpKeyPair = new PgpKeyPair(PublicKeyAlgorithmTag.ECDH, encryptionKeyPair, KeyCreationTime);

            var signatureSubpacketGenerator = CreateSignatureSubpacketGenerator(ExpirationTime);

            PgpKeyRingGenerator keyRingGenerator = new PgpKeyRingGenerator(
                certificationLevel: PgpSignature.PositiveCertification,
                masterKey: signaturePgpKeyPair,
                id: userIdentity,
                encAlgorithm: algorithm,
                rawPassPhrase: Encoding.UTF8.GetBytes(password),
                useSha1: true,
                hashedPackets: signatureSubpacketGenerator.Generate(),
                unhashedPackets: null,
                rand: new SecureRandom());

            var encryptionSubpacketGenerator = CreateEncryptionSubpacketGenerator(ExpirationTime);

            keyRingGenerator.AddSubKey(
                keyPair: encryptionPgpKeyPair,
                hashedPackets: encryptionSubpacketGenerator.Generate(),
                unhashedPackets: null);

            return keyRingGenerator;
        }

        private PgpSignatureSubpacketGenerator CreateSignatureSubpacketGenerator(long expirationTime)
        {
            var subpacketGenerator = new PgpSignatureSubpacketGenerator();

            subpacketGenerator.SetKeyFlags(false, PgpKeyFlags.CanSign | PgpKeyFlags.CanCertify);
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

        private PgpSignatureSubpacketGenerator CreateEncryptionSubpacketGenerator(long expirationTime)
        {
            var subpacketGenerator = new PgpSignatureSubpacketGenerator();

            subpacketGenerator.SetKeyFlags(false, PgpKeyFlags.CanEncryptCommunications | PgpKeyFlags.CanEncryptStorage);
            subpacketGenerator.SetPreferredSymmetricAlgorithms(false, this.EnabledEncryptionAlgorithms.Select(e => (int)e).ToArray());
            subpacketGenerator.SetPreferredHashAlgorithms(false, this.EnabledDigestAlgorithms.Select(e => (int)e).ToArray());

            if (expirationTime > 0)
            {
                subpacketGenerator.SetKeyExpirationTime(false, expirationTime);
                subpacketGenerator.SetSignatureExpirationTime(false, expirationTime);
            }

            return subpacketGenerator;
        }
    }
}
