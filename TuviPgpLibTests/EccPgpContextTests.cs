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

using MimeKit.Cryptography;
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
            ctx.DeriveKeyPair(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity(), "");

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
                ctx.DeriveKeyPair(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity(), "");

                using Stream inputData = new MemoryStream();
                using var messageBody = new TextPart() { Text = TestData.TextContent };
                messageBody.WriteTo(inputData);
                inputData.Position = 0;
                var encryptedMime = ctx.Encrypt(new List<MailboxAddress> { TestData.GetAccount().GetMailbox() }, inputData);
                encryptedMime.WriteTo(encryptedData);
            }

            using (EccPgpContext anotherCtx = await InitializeEccPgpContextAsync().ConfigureAwait(false))
            {
                anotherCtx.DeriveKeyPair(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity(), "");

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
            
            for (int keyIndex = 0; keyIndex < 3; keyIndex++)
            {
                using EccPgpContext ctx = await InitializeEccPgpContextAsync().ConfigureAwait(false);
                
                ctx.DeriveKeyPair(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity(), "", keyIndex);

                var listOfKeys = ctx.GetPublicKeys(new List<MailboxAddress> { TestData.GetAccount().GetMailbox() });
                PgpPublicKey key = listOfKeys.First();

                ECPublicKeyParameters? publicKey = key.GetKey() as ECPublicKeyParameters;
                Assert.That(publicKey, Is.Not.Null, "PublicKey can not be a null");
                Assert.That(ToHex(publicKey.Q.GetEncoded()), Is.EqualTo(TestData.PgpPubKey[keyIndex]),
                                "Public key is not equal to determined");
            }
        }

        [Test]
        public async Task EссCanSignAsync()
        {
            using EccPgpContext ctx = await InitializeEccPgpContextAsync().ConfigureAwait(false);
            Assert.IsFalse(ctx.CanSign(TestData.GetAccount().GetMailbox()));
            ctx.DeriveKeyPair(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity(), "", 0);
            Assert.IsTrue(ctx.CanSign(TestData.GetAccount().GetMailbox()));
        }

        [Test]
        public async Task EссSignAsync()
        {
            using EccPgpContext ctx = await InitializeEccPgpContextAsync().ConfigureAwait(false);
            ctx.DeriveKeyPair(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity(), "");

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
            ctx.DeriveKeyPair(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity(), "");

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
    }
}
