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

using MimeKit.Cryptography;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Crypto.Parameters;
using System.Globalization;

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
            ctx.DeriveKeyPair(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity(), TestData.GetAccount().GetPgpIdentity());

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
                ctx.DeriveKeyPair(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity(), TestData.GetAccount().GetPgpIdentity());

                using Stream inputData = new MemoryStream();
                using var messageBody = new TextPart() { Text = TestData.TextContent };
                messageBody.WriteTo(inputData);
                inputData.Position = 0;
                var encryptedMime = ctx.Encrypt(new List<MailboxAddress> { TestData.GetAccount().GetMailbox() }, inputData);
                encryptedMime.WriteTo(encryptedData);
            }

            using (EccPgpContext anotherCtx = await InitializeEccPgpContextAsync().ConfigureAwait(false))
            {
                anotherCtx.DeriveKeyPair(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity(), TestData.GetAccount().GetPgpIdentity());

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
            ctx.DeriveKeyPair(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity(), TestData.GetAccount().GetPgpIdentity());

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
            Assert.That(ctx.CanSign(TestData.GetAccount().GetMailbox()), Is.False);
            ctx.DeriveKeyPair(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity(), TestData.GetAccount().GetPgpIdentity());
            Assert.That(ctx.CanSign(TestData.GetAccount().GetMailbox()), Is.True);
        }

        [Test]
        public async Task EссSignAsync()
        {
            using EccPgpContext ctx = await InitializeEccPgpContextAsync().ConfigureAwait(false);
            ctx.DeriveKeyPair(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity(), TestData.GetAccount().GetPgpIdentity());

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
            ctx.DeriveKeyPair(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity(), TestData.GetAccount().GetPgpIdentity());

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
                () => ctx.DeriveKeyPair(null, TestData.GetAccount().GetPgpIdentity(), TestData.GetAccount().GetPgpIdentity()));
            Assert.Throws<ArgumentNullException>(
                () => ctx.DeriveKeyPair(TestData.MasterKey, null, null));
        }

        [Test]
        public async Task EссCanSignNullParameterThrowArgumentNullExceptionAsync()
        {
            using EccPgpContext ctx = await InitializeEccPgpContextAsync().ConfigureAwait(false);
            ctx.DeriveKeyPair(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity(), TestData.GetAccount().GetPgpIdentity());
            Assert.That(ctx.CanSign(TestData.GetAccount().GetMailbox()), Is.True);
            Assert.Throws<ArgumentNullException>(
               () => ctx.CanSign(null));
        }

        [Test]
        public async Task EссGetSigningKeyAsync()
        {
            using EccPgpContext ctx = await InitializeEccPgpContextAsync().ConfigureAwait(false);
            ctx.DeriveKeyPair(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity(), TestData.GetAccount().GetPgpIdentity());
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
            ctx.DeriveKeyPair(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity(), TestData.GetAccount().GetPgpIdentity());
            Assert.Throws<ArgumentNullException>(
               () => ctx.GetSigningKey(null));
        }

        const int CoinType = 3630;

        [Test]
        public async Task EccBip44KeyDerivationForDecTest()
        {
            using EccPgpContext ctx = await InitializeEccPgpContextAsync().ConfigureAwait(false);
            int account = 0;
            int channel = 10; // Mail channel
            int index = 0;
            string userIdentity = TestData.GetAccount().GetPgpIdentity();

            ctx.GeneratePgpKeysByBip44(TestData.MasterKey, userIdentity, CoinType, account, channel, index);

            var publicKeys = ctx.EnumeratePublicKeyRings().ToList();
            var secretKeys = ctx.EnumerateSecretKeyRings().ToList();
            Assert.That(publicKeys.Count, Is.GreaterThan(0), "No public keys generated");
            Assert.That(secretKeys.Count, Is.GreaterThan(0), "No secret keys generated");

            // Determinism check: repeated derivation with the same parameters gives the same keys
            using EccPgpContext ctx2 = await InitializeEccPgpContextAsync().ConfigureAwait(false);
            ctx2.GeneratePgpKeysByBip44(TestData.MasterKey, userIdentity, CoinType, account, channel, index);
            var publicKeys2 = ctx2.EnumeratePublicKeyRings().ToList();
            var secretKeys2 = ctx2.EnumerateSecretKeyRings().ToList();
            Assert.That(publicKeys.Count, Is.EqualTo(publicKeys2.Count), "Public key count mismatch");
            Assert.That(secretKeys.Count, Is.EqualTo(secretKeys2.Count), "Secret key count mismatch");
            Assert.That(publicKeys[0].GetPublicKey().GetFingerprint(), Is.EqualTo(publicKeys2[0].GetPublicKey().GetFingerprint()), "Public key fingerprint mismatch");
            Assert.That(secretKeys[0].GetSecretKey().KeyId, Is.EqualTo(secretKeys2[0].GetSecretKey().KeyId), "Secret key id mismatch");
        }

        [Test]
        public async Task DeriveKeyForDecDifferentValidParameters()
        {
            using EccPgpContext ctx = await InitializeEccPgpContextAsync().ConfigureAwait(false);
            string userIdentity = TestData.GetAccount().GetPgpIdentity();
            int[] accounts = { 0, 1 };
            int[] channels = { 10, 20 };
            int[] indices = { 0, 1 };
            foreach (var account in accounts)
            {
                foreach (var channel in channels)
                {
                    foreach (var index in indices)
                    {
                        ctx.GeneratePgpKeysByBip44(TestData.MasterKey, userIdentity, CoinType, account, channel, index);
                        var publicKeys = ctx.EnumeratePublicKeyRings().ToList();
                        var secretKeys = ctx.EnumerateSecretKeyRings().ToList();
                        Assert.That(publicKeys.Count, Is.GreaterThan(0));
                        Assert.That(secretKeys.Count, Is.GreaterThan(0));
                        ctx.Delete(publicKeys[0]);
                        ctx.Delete(secretKeys[0]);
                    }
                }
            }
        }

        [Test]
        public async Task DeriveKeyForDecBoundaryValues()
        {
            using EccPgpContext ctx = await InitializeEccPgpContextAsync().ConfigureAwait(false);
            string userIdentity = TestData.GetAccount().GetPgpIdentity();
            ctx.GeneratePgpKeysByBip44(TestData.MasterKey, userIdentity, 0, 0, 0, 0);
            ctx.GeneratePgpKeysByBip44(TestData.MasterKey, userIdentity, int.MaxValue, int.MaxValue, int.MaxValue, int.MaxValue);
            var publicKeys = ctx.EnumeratePublicKeyRings().ToList();
            var secretKeys = ctx.EnumerateSecretKeyRings().ToList();
            Assert.That(publicKeys.Count, Is.GreaterThan(0));
            Assert.That(secretKeys.Count, Is.GreaterThan(0));
        }

        [Test]
        public async Task DeriveKeyForDecInvalidParametersThrows()
        {
            using EccPgpContext ctx = await InitializeEccPgpContextAsync().ConfigureAwait(false);
            string userIdentity = TestData.GetAccount().GetPgpIdentity();
            Assert.Throws<ArgumentNullException>(() => ctx.GeneratePgpKeysByBip44(null, userIdentity, CoinType, 0, 10, 0));
            Assert.Throws<ArgumentNullException>(() => ctx.GeneratePgpKeysByBip44(TestData.MasterKey, null, CoinType, 0, 10, 0));
            Assert.Throws<ArgumentOutOfRangeException>(() => ctx.GeneratePgpKeysByBip44(TestData.MasterKey, userIdentity, CoinType, -1, 10, 0));
            Assert.Throws<ArgumentOutOfRangeException>(() => ctx.GeneratePgpKeysByBip44(TestData.MasterKey, userIdentity, CoinType, 0, -1, 0));
            Assert.Throws<ArgumentOutOfRangeException>(() => ctx.GeneratePgpKeysByBip44(TestData.MasterKey, userIdentity, CoinType, 0, 10, -1));
        }

        [Test]
        public async Task DeriveKeyForDecUniqueness()
        {
            using EccPgpContext ctx = await InitializeEccPgpContextAsync().ConfigureAwait(false);
            string userIdentity = TestData.GetAccount().GetPgpIdentity();
            ctx.GeneratePgpKeysByBip44(TestData.MasterKey, userIdentity, CoinType, 0, 10, 0);
            var publicKeys1 = ctx.EnumeratePublicKeyRings().Select(x => x.GetPublicKey().GetFingerprint()).ToList();
            var secretKeys1 = ctx.EnumerateSecretKeyRings().Select(x => x.GetSecretKey().KeyId).ToList();
            ctx.GeneratePgpKeysByBip44(TestData.MasterKey, userIdentity, CoinType, 0, 10, 1);
            var publicKeys2 = ctx.EnumeratePublicKeyRings().Select(x => x.GetPublicKey().GetFingerprint()).ToList();
            var secretKeys2 = ctx.EnumerateSecretKeyRings().Select(x => x.GetSecretKey().KeyId).ToList();
            // Check that new keys are unique by fingerprint/KeyId
            bool foundUniquePublic = publicKeys2.Except(publicKeys1).Any();
            bool foundUniqueSecret = secretKeys2.Except(secretKeys1).Any();
            Assert.That(foundUniquePublic, Is.True, "No unique public key generated");
            Assert.That(foundUniqueSecret, Is.True, "No unique secret key generated");
        }

        [Test]
        public async Task DeriveKeyForDecRepeatability()
        {
            using EccPgpContext ctx1 = await InitializeEccPgpContextAsync().ConfigureAwait(false);
            using EccPgpContext ctx2 = await InitializeEccPgpContextAsync().ConfigureAwait(false);
            string userIdentity = TestData.GetAccount().GetPgpIdentity();
            ctx1.GeneratePgpKeysByBip44(TestData.MasterKey, userIdentity, CoinType, 0, 10, 0);
            ctx2.GeneratePgpKeysByBip44(TestData.MasterKey, userIdentity, CoinType, 0, 10, 0);
            var publicKeys1 = ctx1.EnumeratePublicKeyRings().ToList();
            var secretKeys1 = ctx1.EnumerateSecretKeyRings().ToList();
            var publicKeys2 = ctx2.EnumeratePublicKeyRings().ToList();
            var secretKeys2 = ctx2.EnumerateSecretKeyRings().ToList();
            Assert.That(publicKeys1[0].GetPublicKey().GetFingerprint(), Is.EqualTo(publicKeys2[0].GetPublicKey().GetFingerprint()));
            Assert.That(secretKeys1[0].GetSecretKey().KeyId, Is.EqualTo(secretKeys2[0].GetSecretKey().KeyId));
        }

        [Test]
        public async Task DeriveKeyForDecBulkGeneration()
        {
            using EccPgpContext ctx = await InitializeEccPgpContextAsync().ConfigureAwait(false);
            string userIdentity = TestData.GetAccount().GetPgpIdentity();
            for (int i = 0; i < 5; i++)
            {
                ctx.GeneratePgpKeysByBip44(TestData.MasterKey, userIdentity, CoinType, 0, 10, i);
            }
            var publicKeys = ctx.EnumeratePublicKeyRings().ToList();
            var secretKeys = ctx.EnumerateSecretKeyRings().ToList();
            Assert.That(publicKeys.Count, Is.GreaterThanOrEqualTo(5));
            Assert.That(secretKeys.Count, Is.GreaterThanOrEqualTo(5));
        }
    
        private const string ValidTag = "TestTag";

        [Test]
        public void GenerateEccPublicKeyBip44ValidParametersReturnsValidPublicKey()
        {
            // Arrange
            var masterKey = TestData.MasterKey;
            int coin = CoinType;
            int account = 0;
            int channel = 10; // Mail channel
            int index = 0;

            // Act
            var publicKey = EccPgpContext.GenerateEccPublicKey(masterKey, coin, account, channel, index);

            // Assert
            Assert.That(publicKey, Is.Not.Null, "Public key should not be null");
            Assert.That(publicKey.Q, Is.Not.Null, "Public key point should not be null");
            Assert.That(publicKey.PublicKeyParamSet, Is.EqualTo(ECNamedCurveTable.GetOid(EccPgpContext.BitcoinEllipticCurveName)),
                "Public key should use secp256k1 curve");
            Assert.That(publicKey.Q.GetEncoded().Length, Is.GreaterThan(0), "Public key encoding should not be empty");
        }

        [Test]
        public void GenerateEccPublicKeyBip44SameParametersReturnsSameKey()
        {
            // Arrange
            var masterKey = TestData.MasterKey;
            int coin = CoinType;
            int account = 0;
            int channel = 10;
            int index = 0;

            // Act
            var publicKey1 = EccPgpContext.GenerateEccPublicKey(masterKey, coin, account, channel, index);
            var publicKey2 = EccPgpContext.GenerateEccPublicKey(masterKey, coin, account, channel, index);

            // Assert
            string ToHex(byte[] data) => string.Concat(data.Select(x => x.ToString("x2", CultureInfo.CurrentCulture)));
            Assert.That(ToHex(publicKey1.Q.GetEncoded()), Is.EqualTo(ToHex(publicKey2.Q.GetEncoded())),
                "Public keys generated with the same BIP-44 parameters should be identical");
        }

        [Test]
        public void GenerateEccPublicKeyBip44DifferentIndicesReturnsDifferentKeys()
        {
            // Arrange
            var masterKey = TestData.MasterKey;
            int coin = CoinType;
            int account = 0;
            int channel = 10;
            int index1 = 0;
            int index2 = 1;

            // Act
            var publicKey1 = EccPgpContext.GenerateEccPublicKey(masterKey, coin, account, channel, index1);
            var publicKey2 = EccPgpContext.GenerateEccPublicKey(masterKey, coin, account, channel, index2);

            // Assert
            string ToHex(byte[] data) => string.Concat(data.Select(x => x.ToString("x2", CultureInfo.CurrentCulture)));
            Assert.That(ToHex(publicKey1.Q.GetEncoded()), Is.Not.EqualTo(ToHex(publicKey2.Q.GetEncoded())),
                "Public keys generated with different indices should be unique");
        }

        [Test]
        public void GenerateEccPublicKeyBip44NullMasterKeyThrowsArgumentNullException()
        {
            // Arrange
            int coin = CoinType;
            int account = 0;
            int channel = 10;
            int index = 0;

            // Act & Assert
            Assert.Throws<ArgumentNullException>(
                () => EccPgpContext.GenerateEccPublicKey(null, coin, account, channel, index),
                "Null masterKey should throw ArgumentNullException");
        }

        [Test]
        [TestCase(-1, 0, 0, 0, "coin")]
        [TestCase(CoinType, -1, 0, 0, "account")]
        [TestCase(CoinType, 0, -1, 0, "channel")]
        [TestCase(CoinType, 0, 0, -1, "index")]
        public void GenerateEccPublicKeyBip44NegativeParametersThrowsArgumentOutOfRangeException(int coin, int account, int channel, int index, string paramName)
        {
            // Arrange
            var masterKey = TestData.MasterKey;

            // Act & Assert
            var ex = Assert.Throws<ArgumentOutOfRangeException>(
                () => EccPgpContext.GenerateEccPublicKey(masterKey, coin, account, channel, index),
                $"Negative {paramName} should throw ArgumentOutOfRangeException");
            Assert.That(ex.ParamName, Is.EqualTo(paramName), "Exception should indicate the correct parameter name");
        }

        [Test]
        public void GenerateEccPublicKeyBip44BoundaryValuesReturnsValidPublicKey()
        {
            // Arrange
            var masterKey = TestData.MasterKey;
            int coin = int.MaxValue;
            int account = int.MaxValue;
            int channel = int.MaxValue;
            int index = int.MaxValue;

            // Act
            var publicKey = EccPgpContext.GenerateEccPublicKey(masterKey, coin, account, channel, index);

            // Assert
            Assert.That(publicKey, Is.Not.Null, "Public key should not be null for boundary values");
            Assert.That(publicKey.Q, Is.Not.Null, "Public key point should not be null");
            Assert.That(publicKey.PublicKeyParamSet, Is.EqualTo(ECNamedCurveTable.GetOid(EccPgpContext.BitcoinEllipticCurveName)),
                "Public key should use secp256k1 curve");
        }

        [Test]
        public void GenerateEccPublicKeyTagValidParametersReturnsValidPublicKey()
        {
            // Arrange
            var masterKey = TestData.MasterKey;
            string keyTag = ValidTag;

            // Act
            var publicKey = EccPgpContext.GenerateEccPublicKey(masterKey, keyTag);

            // Assert
            Assert.That(publicKey, Is.Not.Null, "Public key should not be null");
            Assert.That(publicKey.Q, Is.Not.Null, "Public key point should not be null");
            Assert.That(publicKey.PublicKeyParamSet, Is.EqualTo(ECNamedCurveTable.GetOid(EccPgpContext.BitcoinEllipticCurveName)),
                "Public key should use secp256k1 curve");
            Assert.That(publicKey.Q.GetEncoded().Length, Is.GreaterThan(0), "Public key encoding should not be empty");
        }

        [Test]
        public void GenerateEccPublicKeyTagSameTagReturnsSameKey()
        {
            // Arrange
            var masterKey = TestData.MasterKey;
            string keyTag = ValidTag;

            // Act
            var publicKey1 = EccPgpContext.GenerateEccPublicKey(masterKey, keyTag);
            var publicKey2 = EccPgpContext.GenerateEccPublicKey(masterKey, keyTag);

            // Assert
            string ToHex(byte[] data) => string.Concat(data.Select(x => x.ToString("x2", CultureInfo.CurrentCulture)));
            Assert.That(ToHex(publicKey1.Q.GetEncoded()), Is.EqualTo(ToHex(publicKey2.Q.GetEncoded())),
                "Public keys generated with the same tag should be identical");
        }

        [Test]
        public void GenerateEccPublicKeyTagDifferentTagsReturnsDifferentKeys()
        {
            // Arrange
            var masterKey = TestData.MasterKey;
            string keyTag1 = ValidTag;
            string keyTag2 = ValidTag + "_different";

            // Act
            var publicKey1 = EccPgpContext.GenerateEccPublicKey(masterKey, keyTag1);
            var publicKey2 = EccPgpContext.GenerateEccPublicKey(masterKey, keyTag2);

            // Assert
            string ToHex(byte[] data) => string.Concat(data.Select(x => x.ToString("x2", CultureInfo.CurrentCulture)));
            Assert.That(ToHex(publicKey1.Q.GetEncoded()), Is.Not.EqualTo(ToHex(publicKey2.Q.GetEncoded())),
                "Public keys generated with different tags should be unique");
        }

        [Test]
        public void GenerateEccPublicKeyTagNullMasterKeyThrowsArgumentNullException()
        {
            // Arrange
            string keyTag = ValidTag;

            // Act & Assert
            Assert.Throws<ArgumentNullException>(
                () => EccPgpContext.GenerateEccPublicKey(null, keyTag),
                "Null masterKey should throw ArgumentNullException");
        }

        [Test]
        public void GenerateEccPublicKeyTagNullTagThrowsArgumentNullException()
        {
            // Arrange
            var masterKey = TestData.MasterKey;

            // Act & Assert
            Assert.Throws<ArgumentException>(
                () => EccPgpContext.GenerateEccPublicKey(masterKey, null),
                "Null keyTag should throw ArgumentNullException");
        }

        [Test]
        public void GenerateEccPublicKeyTagEmptyTagThrowsArgumentException()
        {
            // Arrange
            var masterKey = TestData.MasterKey;
            string keyTag = string.Empty;

            // Act & Assert
            Assert.Throws<ArgumentException>(
                () => EccPgpContext.GenerateEccPublicKey(masterKey, keyTag),
                "Empty keyTag should throw ArgumentException");
        }
    }
}
