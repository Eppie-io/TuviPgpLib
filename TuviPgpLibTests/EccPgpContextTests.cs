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

using MimeKit;
using NUnit.Framework;
using NUnit.Framework.Interfaces;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using TuviPgpLib;
using TuviPgpLibImpl;

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
            return String.Empty;
        }
    }

    internal class EccPgpContextTests
    {
        private EccPgpContext InitializeEccPgpContext()
        {
            var keyStorage = new MockPgpKeyStorage().Get();
            var context = new TestEccPgpContext(keyStorage);
            context.LoadContextAsync().Wait();
            return context;
        }

        [Test]
        public void DeterministicEccKeyDerivation()
        {
            string ToHex(byte[] data) => string.Concat(data.Select(x => x.ToString("x2")));

            for (int i = 0; i < TestData.EccKeyPairs.Length; i++)
            {
                var keyPair = EccPgpContext.DeriveKeyPair(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity(), i);

                var privateKey = keyPair.Private as ECPrivateKeyParameters;
                var publicKey = keyPair.Public as ECPublicKeyParameters;
                if (privateKey == null)
                {
                    throw new Exception("privateKey can not be a null");
                }

                if(publicKey == null)
                {
                    throw new Exception("publicKey can not be a null");
                }

                Assert.That(ToHex(privateKey.D.ToByteArrayUnsigned()), Is.EqualTo(TestData.EccKeyPairs[i].Key),
                                "Private key is not equal to determined");
                Assert.That(ToHex(publicKey.Q.GetEncoded()), Is.EqualTo(TestData.EccKeyPairs[i].Value),
                                "Public key is not equal to determined");
            }
        }

        [Test]
        public void EссEncryptAndDecrypt()
        {
            using EccPgpContext ctx = InitializeEccPgpContext();
            ctx.DeriveKeyPair(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity(), "");

            using Stream inputData = new MemoryStream();
            using Stream encryptedData = new MemoryStream();
            var messageBody = new TextPart() { Text = TestData.TextContent };
            messageBody.WriteTo(inputData);
            inputData.Position = 0;

            var encryptedMime = ctx.Encrypt(new List<MailboxAddress> { TestData.GetAccount().GetMailbox() }, inputData);

            encryptedMime.WriteTo(encryptedData);
            encryptedData.Position = 0;

            var mime = ctx.Decrypt(encryptedData);
            var decryptedBody = mime as TextPart;
            Assert.IsTrue(
                TestData.TextContent.SequenceEqual(decryptedBody?.Text ?? string.Empty),
                "Decrypted content is corrupted");
        }

        [Test]
        public void EccDeterministicKeyPairRestore()
        {
            using Stream encryptedData = new MemoryStream();
            using (EccPgpContext ctx = InitializeEccPgpContext())
            {
                ctx.DeriveKeyPair(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity(), "");

                using Stream inputData = new MemoryStream();
                var messageBody = new TextPart() { Text = TestData.TextContent };
                messageBody.WriteTo(inputData);
                inputData.Position = 0;
                var encryptedMime = ctx.Encrypt(new List<MailboxAddress> { TestData.GetAccount().GetMailbox() }, inputData);
                encryptedMime.WriteTo(encryptedData);
            }

            using (EccPgpContext ctx = InitializeEccPgpContext())
            {
                ctx.DeriveKeyPair(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity(), "");

                encryptedData.Position = 0;
                var mime = ctx.Decrypt(encryptedData);
                var decryptedBody = mime as TextPart;
                Assert.IsTrue(
                    TestData.TextContent.SequenceEqual(decryptedBody?.Text ?? string.Empty),
                    "Data decrypted with restored key is corrupted");
            }
        }
    }
}
