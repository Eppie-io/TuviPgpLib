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

using TuviPgpLib.Entities;

namespace TuviPgpLibTests
{
    public class TuviPgpContextTests
    {
        private static async Task<TuviPgpContext> InitializeTuviPgpContextAsync()
        {
            var keyStorage = new MockPgpKeyStorage().Get();
            var context = new TuviPgpContext(keyStorage);
            await context.LoadContextAsync().ConfigureAwait(false);
            return context;
        }

        [Test]
        public async Task TuviPgpKeysRawImportExportAsync()
        {
            await TuviPgpKeysImportExport(false).ConfigureAwait(false);
        }

        [Test]
        public async Task TuviPgpKeysArmoredImportExportAsync()
        {
            await TuviPgpKeysImportExport(true).ConfigureAwait(false);
        }

        private static async Task TuviPgpKeysImportExport(bool isArmored)
        {
            using Stream encryptedMimeData = new MemoryStream();
            using Stream publicKeyData = new MemoryStream();
            using Stream secretKeyData = new MemoryStream();

            using (TuviPgpContext ctx = await InitializeTuviPgpContextAsync().ConfigureAwait(false))
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

            await EncryptMimeWithImportedPubKeyAsync(publicKeyData, encryptedMimeData, isArmored).ConfigureAwait(false);

            encryptedMimeData.Position = 0;

            await DecryptMimeWithImportedSecretKeyAsync(secretKeyData, encryptedMimeData, isArmored).ConfigureAwait(false);
        }

        [Test]
        public async Task ExportPublicKeyRingByKeyId()
        {
            using Stream encryptedMimeData = new MemoryStream();
            using Stream publicKeyArmored = new MemoryStream();
            using Stream secretKeyData = new MemoryStream();
            using (TuviPgpContext ctx = await InitializeTuviPgpContextAsync().ConfigureAwait(false))
            {
                ctx.DeriveKeyPair(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity(), "");
                var publicKeyId = ctx.GetPublicKeysInfo().First().KeyId;

                ctx.DeriveKeyPair(TestData.MasterKey, TestData.GetSecondAccount().GetPgpIdentity(), "");
                ctx.DeriveKeyPair(TestData.MasterKey, TestData.GetThirdAccount().GetPgpIdentity(), "");
                Assert.That(ctx.GetPublicKeysInfo().Count, Is.EqualTo(3));

                Assert.DoesNotThrowAsync(() => ctx.ExportPublicKeyRingAsync(publicKeyId, publicKeyArmored, default));
                Assert.Greater(publicKeyArmored.Length, 0, "Exported public key is empty");

                ctx.ExportSecretKeys(TestData.GetAccount().GetPgpIdentity(), secretKeyData, true);
                Assert.Greater(secretKeyData.Length, 0, "Exported secret key is empty");
            }

            publicKeyArmored.Position = 0;
            secretKeyData.Position = 0;

            await EncryptMimeWithImportedPubKeyAsync(publicKeyArmored, encryptedMimeData, true).ConfigureAwait(false);

            encryptedMimeData.Position = 0;

            await DecryptMimeWithImportedSecretKeyAsync(secretKeyData, encryptedMimeData, true).ConfigureAwait(false);
        }

        private static async Task EncryptMimeWithImportedPubKeyAsync(Stream pubKeyToImport, Stream encryptedMimeData, bool isKeyArmored)
        {
            using TuviPgpContext ctx = await InitializeTuviPgpContextAsync().ConfigureAwait(false);
            ctx.ImportPublicKeys(pubKeyToImport, isKeyArmored);

            Assert.That(ctx.PublicKeyRingBundle.Count, Is.EqualTo(1), "Public key was not imported");

            using Stream inputData = new MemoryStream();
            using TextPart messageBody = new() { Text = TestData.TextContent };
            messageBody.WriteTo(inputData);
            inputData.Position = 0;
            var mailboxes = new List<MailboxAddress> { TestData.GetAccount().GetMailbox() };
            var encryptedMime = ctx.Encrypt(mailboxes, inputData);
            encryptedMime.WriteTo(encryptedMimeData);
        }

        private static async Task DecryptMimeWithImportedSecretKeyAsync(Stream secretKeyToImport, Stream encryptedMimeData, bool isKeyArmored)
        {
            using TuviPgpContext ctx = await InitializeTuviPgpContextAsync().ConfigureAwait(false);
            ctx.ImportSecretKeys(secretKeyToImport, isKeyArmored);

            Assert.That(ctx.SecretKeyRingBundle.Count, Is.EqualTo(1), "Secret key was not imported");

            var mime = ctx.Decrypt(encryptedMimeData);
            var decryptedBody = mime as TextPart;

            Assert.IsTrue(
                TestData.TextContent.SequenceEqual(decryptedBody?.Text ?? string.Empty),
                "Data decrypted with imported key is corrupted");
        }

        [Test]
        public async Task SecretKeyExistAsync()
        {
            using TuviPgpContext ctx = await InitializeTuviPgpContextAsync().ConfigureAwait(false);
            ctx.DeriveKeyPair(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity(), "");
            bool isKeyExist = ctx.IsSecretKeyExist(TestData.GetAccount().GetUserIdentity());

            Assert.IsTrue(isKeyExist, "Secret key has to exist");
        }

        [Test]
        public async Task SecretKeyNotExistAsync()
        {
            using TuviPgpContext ctx = await InitializeTuviPgpContextAsync().ConfigureAwait(false);
            ctx.DeriveKeyPair(TestData.MasterKey, TestData.WrongPgpIdentity, "");
            bool isKeyExist = ctx.IsSecretKeyExist(TestData.GetAccount().GetUserIdentity());

            Assert.IsFalse(isKeyExist, "Secret key has not to exist");
        }

        [Test]
        public async Task GetPublicKeysInformationAsync()
        {
            using TuviPgpContext ctx = await InitializeTuviPgpContextAsync().ConfigureAwait(false);

            ctx.DeriveKeyPair(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity(), "");
            var keysInfo = ctx.GetPublicKeysInfo();

            Assert.That(keysInfo.Count, Is.EqualTo(1));

            var keyInfo = keysInfo.First();

            Assert.That(keyInfo.UserIdentity, Is.EqualTo(TestData.GetAccount().GetPgpIdentity()), "Incorrect PGP user identity");
            Assert.That(keyInfo.IsMasterKey, Is.EqualTo(true), "Only master keys have to be returned");
        }

        [Test]
        public async Task IsSecretKeyExistNullIdentityThrowArgumentNullExceptionAsync()
        {
            using TuviPgpContext ctx = await InitializeTuviPgpContextAsync().ConfigureAwait(false);
            UserIdentity? nullIdentity = null;
            ctx.DeriveKeyPair(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity(), "");
            Assert.Throws<ArgumentNullException>(() => ctx.IsSecretKeyExist(nullIdentity));
        }

        [Test]
        public async Task ExportSecretKeysNullStreamThrowArgumentNullExceptionAsync()
        {
            using Stream? nullStream = null;
            using TuviPgpContext ctx = await InitializeTuviPgpContextAsync().ConfigureAwait(false);
            Assert.Throws<ArgumentNullException>(() =>
            ctx.ExportSecretKeys(TestData.GetAccount().GetPgpIdentity(), nullStream, true));
        }

        [Test]
        public async Task ExportPublicKeysNullStreamThrowArgumentNullExceptionAsync()
        {
            using Stream? nullStream = null;
            using TuviPgpContext ctx = await InitializeTuviPgpContextAsync().ConfigureAwait(false);
            var identities = new List<UserIdentity> { TestData.GetAccount().GetUserIdentity() };
            Assert.Throws<ArgumentNullException>(() =>
            ctx.ExportPublicKeys(identities, nullStream, true));
        }

        [Test]
        public async Task ExportPublicKeysNullIdentitiesThrowArgumentNullExceptionAsync()
        {
            using Stream publicKeyArmored = new MemoryStream();
            using TuviPgpContext ctx = await InitializeTuviPgpContextAsync().ConfigureAwait(false);
            List<UserIdentity>? identities = null;
            Assert.Throws<ArgumentNullException>(() =>
            ctx.ExportPublicKeys(identities, publicKeyArmored, true));
        }

        [Test]
        public async Task ImportSecretKeysNullStreamThrowArgumentNullExceptionAsync()
        {
            using Stream? nullStream = null;
            using TuviPgpContext ctx = await InitializeTuviPgpContextAsync().ConfigureAwait(false);
            Assert.Throws<ArgumentNullException>(() => ctx.ImportSecretKeys(nullStream, true));
            Assert.Throws<ArgumentNullException>(() => ctx.ImportSecretKeys(nullStream, false));
        }

        [Test]
        public async Task ImportPublicKeysNullStreamThrowArgumentNullExceptionAsync()
        {
            using Stream? nullStream = null;
            using TuviPgpContext ctx = await InitializeTuviPgpContextAsync().ConfigureAwait(false);
            Assert.Throws<ImportPublicKeyException>(() => ctx.ImportPublicKeys(nullStream, true));
            Assert.Throws<ImportPublicKeyException>(() => ctx.ImportPublicKeys(nullStream, false));
        }
    }
}
