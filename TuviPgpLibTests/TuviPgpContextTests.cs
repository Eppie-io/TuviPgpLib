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
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Mail;
using System.Text;
using System.Threading.Tasks;
using TuviPgpLibImpl;
using Entities;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using TuviPgpLib.Entities;

namespace TuviPgpLibTests
{
    internal class TuviPgpContextTests
    {
        private TuviPgpContext InitializeTuviPgpContext()
        {
            var keyStorage = new MockPgpKeyStorage().Get();
            var context = new TuviPgpContext(keyStorage);
            context.LoadContextAsync().Wait();
            return context;
        }

        [Test]
        public void TuviPgpKeysRawImportExport()
        {
            TuviPgpKeysImportExport(false);
        }

        [Test]
        public void TuviPgpKeysArmoredImportExport()
        {
            TuviPgpKeysImportExport(true);
        }

        private void TuviPgpKeysImportExport(bool isArmored)
        {
            using Stream encryptedMimeData = new MemoryStream();
            using Stream publicKeyData = new MemoryStream();
            using Stream secretKeyData = new MemoryStream();

            using (TuviPgpContext ctx = InitializeTuviPgpContext())
            {
                var identities = new List<UserIdentity> { TestData.GetAccount().GetUserIdentity() };

                ctx.DeriveKeyPair(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity(), "");
                ctx.ExportPublicKeys(identities, publicKeyData, isArmored);
                ctx.ExportSecretKeys(TestData.GetAccount().GetPgpIdentity(), secretKeyData, isArmored);

                Assert.Greater(publicKeyData.Length, 0, "Exported public key is empty");
                Assert.Greater(secretKeyData.Length, 0, "Exported secret key is empty");
            }

            publicKeyData.Position = 0;
            secretKeyData.Position = 0;

            EncryptMimeWithImportedPubKey(publicKeyData, encryptedMimeData, isArmored);

            encryptedMimeData.Position = 0;

            DecryptMimeWithImportedSecretKey(secretKeyData, encryptedMimeData, isArmored);
        }

        [Test]
        public void ExportPublicKeyRingByKeyId()
        {
            using Stream encryptedMimeData = new MemoryStream();
            using Stream publicKeyArmored = new MemoryStream();
            using Stream secretKeyData = new MemoryStream();
            using (TuviPgpContext ctx = InitializeTuviPgpContext())
            {
                ctx.DeriveKeyPair(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity(), "");
                var publicKeyId = ctx.GetPublicKeysInfo().First().KeyId;

                Assert.DoesNotThrowAsync(() => ctx.ExportPublicKeyRingAsync(publicKeyId, publicKeyArmored, default));
                Assert.Greater(publicKeyArmored.Length, 0, "Exported public key is empty");

                ctx.ExportSecretKeys(TestData.GetAccount().GetPgpIdentity(), secretKeyData, true);
                Assert.Greater(secretKeyData.Length, 0, "Exported secret key is empty");
            }

            publicKeyArmored.Position = 0;
            secretKeyData.Position = 0;

            EncryptMimeWithImportedPubKey(publicKeyArmored, encryptedMimeData, true);

            encryptedMimeData.Position = 0;

            DecryptMimeWithImportedSecretKey(secretKeyData, encryptedMimeData, true);
        }

        private void EncryptMimeWithImportedPubKey(Stream pubKeyToImport, Stream encryptedMimeData, bool isKeyArmored)
        {
            using TuviPgpContext ctx = InitializeTuviPgpContext();
            ctx.ImportPublicKeys(pubKeyToImport, isKeyArmored);

            Assert.That(ctx.PublicKeyRingBundle.Count, Is.EqualTo(1), "Public key was not imported");

            using Stream inputData = new MemoryStream();
            var messageBody = new TextPart() { Text = TestData.TextContent };
            messageBody.WriteTo(inputData);
            inputData.Position = 0;
            var mailboxes = new List<MailboxAddress> { TestData.GetAccount().GetMailbox() };
            var encryptedMime = ctx.Encrypt(mailboxes, inputData);
            encryptedMime.WriteTo(encryptedMimeData);
        }

        private void DecryptMimeWithImportedSecretKey(Stream secretKeyToImport, Stream encryptedMimeData, bool isKeyArmored)
        {
            using TuviPgpContext ctx = InitializeTuviPgpContext();
            ctx.ImportSecretKeys(secretKeyToImport, isKeyArmored);

            Assert.That(ctx.SecretKeyRingBundle.Count, Is.EqualTo(1), "Secret key was not imported");

            var mime = ctx.Decrypt(encryptedMimeData);
            var decryptedBody = mime as TextPart;

            Assert.IsTrue(
                TestData.TextContent.SequenceEqual(decryptedBody?.Text ?? string.Empty),
                "Data decrypted with imported key is corrupted");
        }

        [Test]
        public void SecretKeyExist()
        {
            using TuviPgpContext ctx = InitializeTuviPgpContext();
            ctx.DeriveKeyPair(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity(), "");
            bool isKeyExist = ctx.IsSecretKeyExist(TestData.GetAccount().GetUserIdentity());

            Assert.IsTrue(isKeyExist, "Secret key has to exist");
        }

        [Test]
        public void SecretKeyNotExist()
        {
            using TuviPgpContext ctx = InitializeTuviPgpContext();
            ctx.DeriveKeyPair(TestData.MasterKey, TestData.WrongPgpIdentity, "");
            bool isKeyExist = ctx.IsSecretKeyExist(TestData.GetAccount().GetUserIdentity());

            Assert.IsFalse(isKeyExist, "Secret key has not to exist");
        }

        [Test]
        public void GetPublicKeysInformation()
        {
            using TuviPgpContext ctx = InitializeTuviPgpContext();

            ctx.DeriveKeyPair(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity(), "");
            var keysInfo = ctx.GetPublicKeysInfo();

            Assert.That(keysInfo.Count, Is.EqualTo(1));

            var keyInfo = keysInfo.First();

            Assert.That(keyInfo.UserIdentity, Is.EqualTo(TestData.GetAccount().GetPgpIdentity()), "Incorrect PGP user identity");
            Assert.That(keyInfo.IsMasterKey, Is.EqualTo(true), "Only master keys have to be returned");
        }

        [Test]
        public void IsSecretKeyExistNullIdentityThrowArgumentNullException()
        {
            using TuviPgpContext ctx = InitializeTuviPgpContext();
            UserIdentity? nullIdentity = null;
            ctx.DeriveKeyPair(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity(), "");
            Assert.Throws<ArgumentNullException>(() => ctx.IsSecretKeyExist(nullIdentity));
        }

        [Test]
        public void ExportSecretKeysNullStreamThrowArgumentNullException()
        {
            using Stream? nullStream = null;
            using TuviPgpContext ctx = InitializeTuviPgpContext();
            Assert.Throws<ArgumentNullException>(() =>
            ctx.ExportSecretKeys(TestData.GetAccount().GetPgpIdentity(), nullStream, true));
        }

        [Test]
        public void ExportPublicKeysNullStreamThrowArgumentNullException()
        {
            using Stream? nullStream = null;
            using TuviPgpContext ctx = InitializeTuviPgpContext();
            var identities = new List<UserIdentity> { TestData.GetAccount().GetUserIdentity() };
            Assert.Throws<ArgumentNullException>(() =>
            ctx.ExportPublicKeys(identities, nullStream, true));
        }

        [Test]
        public void ExportPublicKeysNullIdentitiesThrowArgumentNullException()
        {
            using Stream publicKeyArmored = new MemoryStream();
            using TuviPgpContext ctx = InitializeTuviPgpContext();
            List<UserIdentity>? identities = null;
            Assert.Throws<ArgumentNullException>(() =>
            ctx.ExportPublicKeys(identities, publicKeyArmored, true));
        }

        [Test]
        public void ImportSecretKeysNullStreamThrowArgumentNullException()
        {
            using Stream? nullStream = null;
            using TuviPgpContext ctx = InitializeTuviPgpContext();
            Assert.Throws<ArgumentNullException>(() => ctx.ImportSecretKeys(nullStream, true));
            Assert.Throws<ArgumentNullException>(() => ctx.ImportSecretKeys(nullStream, false));
        }

        [Test]
        public void ImportPublicKeysNullStreamThrowArgumentNullException()
        {
            using Stream? nullStream = null;
            using TuviPgpContext ctx = InitializeTuviPgpContext();
            Assert.Throws<ImportPublicKeyException>(() => ctx.ImportPublicKeys(nullStream, true));
            Assert.Throws<ImportPublicKeyException>(() => ctx.ImportPublicKeys(nullStream, false));
        }
    }
}
