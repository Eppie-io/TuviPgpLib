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

using KeyDerivationLib;
using MimeKit.Cryptography;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.Globalization;
using NBitcoin;
using Org.BouncyCastle.Math.EC.Multiplier;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Crypto;
using static Org.BouncyCastle.Asn1.Cmp.Challenge;

namespace TuviPgpLibTests
{
    internal class TestEccPgpContext : EccPgpContext
    {
        public TestEccPgpContext(IKeyStorage storage)
            : base(storage)
        {
        }

        protected override string GetPasswordForKey(PgpSecretKey key)
        {
            return string.Empty;
        }
    }

    public class EccPgpContextTests
    {
        private static async Task<EccPgpContext> InitializeEccPgpContextAsync()
        {
            var keyStorage = new MockPgpKeyStorage().Get();
            var context = new TestEccPgpContext(keyStorage);
            await context.LoadContextAsync().ConfigureAwait(false);
            return context;
        }

        [Test]
        public async Task EссEncryptAndDecryptAsync()
        {
            using EccPgpContext ctx = await InitializeEccPgpContextAsync().ConfigureAwait(false);
            ctx.DeriveKeyPair(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity());

            using Stream inputData = new MemoryStream();
            using Stream encryptedData = new MemoryStream();
            using var messageBody = new TextPart() { Text = TestData.TextContent };
            messageBody.WriteTo(inputData);
            inputData.Position = 0;

            var encryptedMime = ctx.Encrypt(new List<MailboxAddress> { TestData.GetAccount().GetMailbox() }, inputData);

            encryptedMime.WriteTo(encryptedData);
            encryptedData.Position = 0;

            var mime = ctx.Decrypt(encryptedData);
            var decryptedBody = mime as TextPart;
            Assert.That(
                TestData.TextContent.SequenceEqual(decryptedBody?.Text ?? string.Empty), Is.True,
                "Decrypted content is corrupted");
        }

        [Test]
        public async Task EccDeterministicKeyPairRestoreAsync()
        {
            using Stream encryptedData = new MemoryStream();
            using (EccPgpContext ctx = await InitializeEccPgpContextAsync().ConfigureAwait(false))
            {
                ctx.DeriveKeyPair(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity());

                using Stream inputData = new MemoryStream();
                using var messageBody = new TextPart() { Text = TestData.TextContent };
                messageBody.WriteTo(inputData);
                inputData.Position = 0;
                var encryptedMime = ctx.Encrypt(new List<MailboxAddress> { TestData.GetAccount().GetMailbox() }, inputData);
                encryptedMime.WriteTo(encryptedData);
            }

            using (EccPgpContext anotherCtx = await InitializeEccPgpContextAsync().ConfigureAwait(false))
            {
                anotherCtx.DeriveKeyPair(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity());

                encryptedData.Position = 0;
                var mime = anotherCtx.Decrypt(encryptedData);
                var decryptedBody = mime as TextPart;
                Assert.That(
                    TestData.TextContent.SequenceEqual(decryptedBody?.Text ?? string.Empty), Is.True,
                    "Data decrypted with restored key is corrupted");
            }
        }

        [Test]
        public async Task DeterministicEccKeyDerivation()
        {
            string ToHex(byte[] data) => string.Concat(data.Select(x => x.ToString("x2", CultureInfo.CurrentCulture)));

            using EccPgpContext ctx = await InitializeEccPgpContextAsync().ConfigureAwait(false);
            ctx.DeriveKeyPair(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity());

            var allPublicKeys = ctx.EnumerateSecretKeys().ToList();
            Assert.That(allPublicKeys.Count, Is.EqualTo(3));
            Assert.That(KeysEquals(allPublicKeys[0], allPublicKeys[1]), Is.False);
            Assert.That(KeysEquals(allPublicKeys[0], allPublicKeys[2]), Is.False);
            Assert.That(KeysEquals(allPublicKeys[1], allPublicKeys[2]), Is.False);

            var listOfKeys = ctx.GetPublicKeys(new List<MailboxAddress> { TestData.GetAccount().GetMailbox() });
            PgpPublicKey key = listOfKeys.First();
            ECPublicKeyParameters? publicKey = key.GetKey() as ECPublicKeyParameters;
            Assert.That(publicKey, Is.Not.Null, "PublicKey can not be a null");
            Assert.That(ToHex(publicKey.Q.GetEncoded()), Is.EqualTo(TestData.PgpPubKey),
                            "Public key is not equal to determined");

            bool KeysEquals(PgpSecretKey left, PgpSecretKey right)
            {
                var keyLeft = ((ECPublicBcpgKey)left.PublicKey.PublicKeyPacket.Key).EncodedPoint;
                var keyRight = ((ECPublicBcpgKey)right.PublicKey.PublicKeyPacket.Key).EncodedPoint;
                return Equals(keyLeft, keyRight);
            }
        }

        [Test]
        public async Task EссCanSignAsync()
        {
            using EccPgpContext ctx = await InitializeEccPgpContextAsync().ConfigureAwait(false);
            Assert.IsFalse(ctx.CanSign(TestData.GetAccount().GetMailbox()));
            ctx.DeriveKeyPair(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity());
            Assert.IsTrue(ctx.CanSign(TestData.GetAccount().GetMailbox()));
        }

        [Test]
        public async Task EссSignAsync()
        {
            using EccPgpContext ctx = await InitializeEccPgpContextAsync().ConfigureAwait(false);
            ctx.DeriveKeyPair(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity());

            using Stream inputData = new MemoryStream();
            using Stream encryptedData = new MemoryStream();
            using var messageBody = new TextPart() { Text = TestData.TextContent };
            messageBody.WriteTo(inputData);
            inputData.Position = 0;

            var signedMime = ctx.Sign(TestData.GetAccount().GetMailbox(), DigestAlgorithm.Sha512, inputData);
            inputData.Position = 0;
            signedMime.WriteTo(encryptedData);
            encryptedData.Position = 0;
            var signatures = ctx.Verify(inputData, encryptedData);

            foreach (IDigitalSignature signature in signatures)
            {
                Assert.That(signature.Verify(), Is.True);
            }
        }

        [Test]
        public async Task EссEncryptAndSignAsync()
        {
            using EccPgpContext ctx = await InitializeEccPgpContextAsync().ConfigureAwait(false);
            ctx.DeriveKeyPair(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity());

            using Stream inputData = new MemoryStream();
            using Stream encryptedData = new MemoryStream();
            using var messageBody = new TextPart() { Text = TestData.TextContent };
            messageBody.WriteTo(inputData);
            inputData.Position = 0;

            var signedMime = ctx.SignAndEncrypt(
                signer: TestData.GetAccount().GetMailbox(),
                digestAlgo: DigestAlgorithm.Sha512,
                recipients: new List<MailboxAddress>() { TestData.GetAccount().GetMailbox() },
                content: inputData);

            inputData.Position = 0;
            signedMime.WriteTo(encryptedData);
            encryptedData.Position = 0;
            ctx.Decrypt(encryptedData, out DigitalSignatureCollection signatures);

            foreach (IDigitalSignature signature in signatures)
            {
                Assert.That(signature.Verify(), Is.True);
            }
        }

        [Test]
        public async Task KeyDerivationNullParametersThrowArgumentNullExceptionAsync()
        {
            using EccPgpContext ctx = await InitializeEccPgpContextAsync().ConfigureAwait(false);
            Assert.Throws<ArgumentNullException>(
                () => ctx.DeriveKeyPair(null, TestData.GetAccount().GetPgpIdentity()));
            Assert.Throws<ArgumentNullException>(
                () => ctx.DeriveKeyPair(TestData.MasterKey, null));
        }

        [Test]
        public async Task EссCanSignNullParameterThrowArgumentNullExceptionAsync()
        {
            using EccPgpContext ctx = await InitializeEccPgpContextAsync().ConfigureAwait(false);
            ctx.DeriveKeyPair(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity());
            Assert.That(ctx.CanSign(TestData.GetAccount().GetMailbox()), Is.True);
            Assert.Throws<ArgumentNullException>(
               () => ctx.CanSign(null));
        }

        [Test]
        public async Task EссGetSigningKeyAsync()
        {
            using EccPgpContext ctx = await InitializeEccPgpContextAsync().ConfigureAwait(false);
            ctx.DeriveKeyPair(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity());
            Assert.That(ctx.GetSigningKey(TestData.GetAccount().GetMailbox()), Is.Not.Null);
        }

        [Test]
        public async Task EссCanSignWrongParameterThrowExceptionsAsync()
        {
            using EccPgpContext ctx = await InitializeEccPgpContextAsync().ConfigureAwait(false);
            Assert.Throws<PrivateKeyNotFoundException>(
               () => ctx.GetSigningKey(TestData.GetAccount().GetMailbox()));
            Assert.Throws<ArgumentNullException>(
               () => ctx.GetSigningKey(null));
            ctx.DeriveKeyPair(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity());
            Assert.Throws<ArgumentNullException>(
               () => ctx.GetSigningKey(null));
        }




        [Test]
        public async Task EthereumTest()
        {
            byte[] data = new byte[] { 196, 247, 123, 74, 159, 90, 13, 179, 167, 255, 195, 89, 158, 97, 
                190, 249, 134, 3, 122, 233, 167, 204, 25, 114, 161, 13, 85, 192, 48, 39, 0, 32 };


            //byte[] pubKey = new byte[] { 4, 20, 172, 190, 90, 6, 198, 130, 16, 252, 187, 119, 118, 63, 
            //    150, 18, 228, 90, 82, 105, 144, 174, 182, 157, 105, 45, 112, 95, 39, 111, 85, 138, 90, 
            //    230, 130, 104, 233, 56, 155, 176, 153, 237, 90, 200, 77, 141, 104, 97, 17, 15, 99, 100, 
            //    79, 110, 91, 68, 126, 63, 134, 180, 186, 181, 222, 224, 17 };
            
            
            using EccPgpContext ctx = await InitializeEccPgpContextAsync().ConfigureAwait(false);
            ctx.DeriveEthereumKeyPair(data, TestData.GetAccount().GetPgpIdentity());

            using Stream inputData = new MemoryStream();
            using Stream encryptedData = new MemoryStream();
            using var messageBody = new TextPart() { Text = TestData.TextContent };
            messageBody.WriteTo(inputData);
            inputData.Position = 0;

            var encryptedMime = ctx.Encrypt(new List<MailboxAddress> { TestData.GetAccount().GetMailbox() }, inputData);

            encryptedMime.WriteTo(encryptedData);
            encryptedData.Position = 0;

            var mime = ctx.Decrypt(encryptedData);
            var decryptedBody = mime as TextPart;
            Assert.That(
                TestData.TextContent.SequenceEqual(decryptedBody?.Text ?? string.Empty), Is.True,
                "Decrypted content is corrupted");
        }

        [Test]
        public async Task EthereumTest2()
        {
            byte[] data = new byte[] { 196, 247, 123, 74, 159, 90, 13, 179, 167, 255, 195, 89, 158, 97,
                190, 249, 134, 3, 122, 233, 167, 204, 25, 114, 161, 13, 85, 192, 48, 39, 0, 32 };

            byte[] pubKey = new byte[] { 4, 20, 172, 190, 90, 6, 198, 130, 16, 252, 187, 119, 118, 63,
                150, 18, 228, 90, 82, 105, 144, 174, 182, 157, 105, 45, 112, 95, 39, 111, 85, 138, 90,
                230, 130, 104, 233, 56, 155, 176, 153, 237, 90, 200, 77, 141, 104, 97, 17, 15, 99, 100,
                79, 110, 91, 68, 126, 63, 134, 180, 186, 181, 222, 224, 17 };

            var key1 = CreatePrivateKey(data, PublicKeyAlgorithmTag.ECDH);
            var key2 = CreatePublicKey(pubKey, PublicKeyAlgorithmTag.ECDH);
            
            var key3 = CreatePrivateKey(data, PublicKeyAlgorithmTag.ECDsa);
            var key4 = CreatePublicKey(pubKey, PublicKeyAlgorithmTag.ECDsa);

            //IList<PgpSecretKey> keys = new List<PgpSecretKey>();

            //keys.Add(new PgpSecretKey(certificationLevel: 1,
            //    new PgpKeyPair(key4, key3), TestData.GetAccount().GetPgpIdentity(),
            //    SymmetricKeyAlgorithmTag.Aes128, Array.Empty<byte>(), false, null, null, new SecureRandom()));
            
            //keys.Add(new PgpSecretKey((keyPair.PrivateKey, new PgpPublicKey(keyPair.PublicKey, null, subSigs), encAlgorithm,
            //        rawPassPhrase, false, useSha1, rand, false));
            //new PgpSecretKeyRing()

            //var pgpkeyring = new PgpSecretKeyRing()

            using EccPgpContext ctx = await InitializeEccPgpContextAsync().ConfigureAwait(false);
            
            //context doesn't encrypt becouse couldn't find the key (it's not connected with email)
            //using Stream keyStream = new MemoryStream();
            //key2.Encode(keyStream);
            //keyStream.Position = 0;
            //var ring = new PgpPublicKeyRing(keyStream);
            //ctx.Import(ring);

            using Stream inputData = new MemoryStream();
            using Stream encryptedData = new MemoryStream();
            using var messageBody = new TextPart() { Text = TestData.TextContent };
            messageBody.WriteTo(inputData);
            inputData.Position = 0;

            //var encryptedMime = ctx.Encrypt(new List<MailboxAddress> { TestData.GetAccount().GetMailbox() }, inputData);
            var encryptedMime = ctx.Encrypt(new List<PgpPublicKey> { key2 }, inputData);

            encryptedMime.WriteTo(encryptedData);
            encryptedData.Position = 0;

            ctx.DeriveEthereumKeyPair(data, TestData.GetAccount().GetPgpIdentity());

            var mime = ctx.Decrypt(encryptedData);
            var decryptedBody = mime as TextPart;
            Assert.That(
                TestData.TextContent.SequenceEqual(decryptedBody?.Text ?? string.Empty), Is.True,
                "Decrypted content is corrupted");
        }

        public const string BitcoinEllipticCurveName = "secp256k1";
        private readonly DateTime KeyCreationTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
        public const long ExpirationTime = 0;


        private PgpPrivateKey CreatePrivateKey(byte[] data, PublicKeyAlgorithmTag algoTag)
        {
            const string algorithm = "EC";

            // curveOid - Curve object identifier
            DerObjectIdentifier curveOid = ECNamedCurveTable.GetOid(BitcoinEllipticCurveName);
            ECKeyGenerationParameters keyParams = new ECKeyGenerationParameters(curveOid, new SecureRandom());

            ECPrivateKeyParameters privateKey = new ECPrivateKeyParameters(algorithm, new BigInteger(1, data), keyParams.PublicKeyParamSet);
            ECMultiplier multiplier = new FixedPointCombMultiplier();
            ECPoint q = multiplier.Multiply(keyParams.DomainParameters.G, privateKey.D);
            ECPublicKeyParameters publicKey = new ECPublicKeyParameters(algorithm, q, keyParams.PublicKeyParamSet);

            PgpKeyPair pgpKeyPair = new PgpKeyPair(algoTag, new AsymmetricCipherKeyPair(publicKey, privateKey), KeyCreationTime);
            //var key = new PgpPrivateKey()
            return pgpKeyPair.PrivateKey;
        }

        private PgpPublicKey CreatePublicKey(byte[] data, PublicKeyAlgorithmTag algoTag)
        {
            const string algorithm = "EC";

            //byte[] childKey = DerivationKeyFactory.DerivePrivateChildKey(derivationKey, keyIndex);

            // curveOid - Curve object identifier
            DerObjectIdentifier curveOid = ECNamedCurveTable.GetOid(BitcoinEllipticCurveName);
            ECKeyGenerationParameters keyParams = new ECKeyGenerationParameters(curveOid, new SecureRandom());

            //ECPrivateKeyParameters privateKey = new ECPrivateKeyParameters(algorithm, new BigInteger(1, key), keyParams.PublicKeyParamSet);

            ECPoint q = keyParams.DomainParameters.Curve.DecodePoint(data);


            //ECMultiplier multiplier = new FixedPointCombMultiplier();
            //ECPoint q = multiplier.Multiply(keyParams.DomainParameters.G, privateKey.D);
            ECPublicKeyParameters publicKey = new ECPublicKeyParameters(algorithm, q, keyParams.PublicKeyParamSet);
            return new PgpPublicKey(algoTag, publicKey, KeyCreationTime);
        }
    }
}
