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
    public class EntitiesTests
    {
        private static async Task<TuviPgpContext> InitializeTuviPgpContextAsync()
        {
            var keyStorage = new MockPgpKeyStorage().Get();
            var context = new TuviPgpContext(keyStorage);
            await context.LoadContextAsync().ConfigureAwait(false);
            return context;
        }

        [Test]
        public void KeyRingBundleTest()
        {
            var keyRingBundle = new PgpKeyBundle { Data = new byte[] { 1, 2, 3} };
            Assert.That(new byte[] {1,2,3}.SequenceEqual(keyRingBundle.Data), Is.True);
            Assert.That(keyRingBundle.Equals(keyRingBundle), Is.True); 
            var anotherKeyRingBundle = new PgpKeyBundle { Data = new byte[] { 1, 2, 3 } };
            Assert.That(keyRingBundle.Equals(anotherKeyRingBundle), Is.True);
            var oneMoreKeyRingBundle = new PgpKeyBundle { Data = new byte[] { 1, 2, 3, 4, 5 } };
            Assert.That(keyRingBundle.Equals(oneMoreKeyRingBundle), Is.False);
        }

        [Test]
        public async Task PgpKeyInfoTest()
        {
            using (TuviPgpContext ctx = await InitializeTuviPgpContextAsync().ConfigureAwait(false))
            {
                ctx.GeneratePgpKeysByTagOld(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity(), TestData.GetAccount().GetPgpIdentity());
                var publicKeyInfo = ctx.GetPublicKeysInfo().First();
                Assert.That(publicKeyInfo.Algorithm, Is.EqualTo("ECDsa"));
                Assert.That(publicKeyInfo.BitStrength, Is.EqualTo(256));
                Assert.That(publicKeyInfo.CreationTime, Is.EqualTo(new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc)));
                Assert.That(publicKeyInfo.Fingerprint, Is.EqualTo("8F90CB850F69B6A614C879CE37A8DD28527585C4"));
                Assert.That(publicKeyInfo.IsEncryptionKey, Is.False);
                Assert.That(publicKeyInfo.IsMasterKey, Is.True);
                Assert.That(publicKeyInfo.IsRevoked, Is.False);
                Assert.That(publicKeyInfo.KeyId, Is.EqualTo(4010698633425290692));
                Assert.That(publicKeyInfo.UserIdentity, Is.EqualTo(TestData.GetAccount().GetPgpIdentity()));
                Assert.That(publicKeyInfo.ValidSeconds, Is.EqualTo(0));
                Assert.That(publicKeyInfo.IsNeverExpires(), Is.True);
            }
        }

        [Test]
        public void ExtensionsExceptions()
        {
            PgpPublicKey? key = null;

            Assert.Throws<ArgumentNullException>(() => key.CreatePgpKeyInfo());
            Assert.That(key.GetUserIdentity(), Is.EqualTo(String.Empty));
        }
    }
}
