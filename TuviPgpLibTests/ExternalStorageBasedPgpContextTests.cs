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


using Org.BouncyCastle.Bcpg.OpenPgp;
using TuviPgpLib;
using TuviPgpLibImpl;

namespace TuviPgpLibTests
{
    internal class TestPgpContext : ExternalStorageBasedPgpContext
    {
        public TestPgpContext(IKeyStorage storage)
            : base(storage)
        {
        }

        protected override string GetPasswordForKey(PgpSecretKey key)
        {
            return string.Empty;
        }
    }

    internal class ExternalStorageBasedPgpContextTests
    {
        private ExternalStorageBasedPgpContext InitializeTestPgpContext()
        {
            var keyStorage = new MockPgpKeyStorage().Get();
            var context = new TestPgpContext(keyStorage);
            context.LoadContextAsync().Wait();
            return context;
        }

        [Test]
        public void ImportPgpPublicKeyRing()
        {
            PgpPublicKeyRing testKeyRing;

            using (var ctx = InitializeTestPgpContext())
            {
                ctx.GenerateKeyPair(TestData.GetAccount().GetMailbox(), "");
                testKeyRing = ctx.EnumeratePublicKeyRings().First();
            }

            using (var anotherCtx = InitializeTestPgpContext())
            {
                Assert.That(anotherCtx.EnumeratePublicKeyRings().Count(), Is.EqualTo(0), "Initialized context is not empty");

                anotherCtx.Import(testKeyRing);
                Assert.That(anotherCtx.EnumeratePublicKeyRings().Count(), Is.EqualTo(1), "Key ring was not imported");
                Assert.That(anotherCtx.EnumeratePublicKeyRings().First(), Is.EqualTo(testKeyRing), "Imported keyring is corrupted");
            }
        }

        [Test]
        public void ImportPgpPublicKeyRingBundle()
        {
            PgpPublicKeyRing testKeyRing;

            using (var ctx = InitializeTestPgpContext())
            {
                ctx.GenerateKeyPair(TestData.GetAccount().GetMailbox(), "");
                testKeyRing = ctx.EnumeratePublicKeyRings().First();
            }

            using (var anotherCtx = InitializeTestPgpContext())
            {
                Assert.That(anotherCtx.EnumeratePublicKeyRings().Count(), Is.EqualTo(0), "Initialized context is not empty");

                var keyRingBundle = PgpPublicKeyRingBundle.AddPublicKeyRing(new PgpPublicKeyRingBundle(Array.Empty<byte>()), testKeyRing);

                anotherCtx.Import(keyRingBundle);
                Assert.That(anotherCtx.EnumeratePublicKeyRings().Count(), Is.EqualTo(1), "Key ring bundle was not imported");
                Assert.That(anotherCtx.EnumeratePublicKeyRings().First(), Is.EqualTo(testKeyRing), "Imported keyring is corrupted");
            }
        }

        [Test]
        public void ImportPgpSecretKeyRing()
        {
            PgpSecretKeyRing testKeyRing;

            using (var ctx = InitializeTestPgpContext())
            {
                ctx.GenerateKeyPair(TestData.GetAccount().GetMailbox(), "");
                testKeyRing = ctx.EnumerateSecretKeyRings().First();
            }

            using (var anotherCtx = InitializeTestPgpContext())
            {
                Assert.That(anotherCtx.EnumerateSecretKeyRings().Count(), Is.EqualTo(0), "Initialized context is not empty");

                anotherCtx.Import(testKeyRing);
                Assert.That(anotherCtx.EnumerateSecretKeyRings().Count(), Is.EqualTo(1), "Key ring was not imported");
                Assert.That(anotherCtx.EnumerateSecretKeyRings().First(), Is.EqualTo(testKeyRing), "Imported keyring is corrupted");
            }
        }

        [Test]
        public void ImportPgpSecretKeyRingBundle()
        {
            PgpSecretKeyRing testKeyRing;

            using (var ctx = InitializeTestPgpContext())
            {
                ctx.GenerateKeyPair(TestData.GetAccount().GetMailbox(), "");
                testKeyRing = ctx.EnumerateSecretKeyRings().First();
            }

            using (var anotherCtx = InitializeTestPgpContext())
            {
                var mailboxes = new List<MailboxAddress> { TestData.GetAccount().GetMailbox() };
                Assert.That(anotherCtx.EnumerateSecretKeyRings().Count(), Is.EqualTo(0), "Initialized context is not empty");

                var keyRingBundle = PgpSecretKeyRingBundle.AddSecretKeyRing(new PgpSecretKeyRingBundle(Array.Empty<byte>()), testKeyRing);

                anotherCtx.Import(keyRingBundle);
                Assert.That(anotherCtx.EnumerateSecretKeyRings().Count(), Is.EqualTo(1), "Key ring bundle was not imported");
                Assert.That(anotherCtx.EnumerateSecretKeyRings().First(), Is.EqualTo(testKeyRing), "Imported keyring is corrupted");
            }
        }

        [Test]
        public void DeletePgpPublicKeyRing()
        {
            using (var ctx = InitializeTestPgpContext())
            {
                ctx.GenerateKeyPair(TestData.GetAccount().GetMailbox(), "");

                Assert.That(ctx.EnumeratePublicKeyRings().Count(), Is.EqualTo(1), "Initialized context is empty");

                ctx.Delete(ctx.EnumeratePublicKeyRings().First());
                Assert.That(ctx.EnumeratePublicKeyRings().Count(), Is.EqualTo(0), "Key ring was not deleted");
            }
        }

        [Test]
        public void DeletePgpSecretKeyRing()
        {
            using (var ctx = InitializeTestPgpContext())
            {
                ctx.GenerateKeyPair(TestData.GetAccount().GetMailbox(), "");

                Assert.That(ctx.EnumerateSecretKeyRings().Count(), Is.EqualTo(1), "Initialized context is empty");

                ctx.Delete(ctx.EnumerateSecretKeyRings().First());
                Assert.That(ctx.EnumerateSecretKeyRings().Count(), Is.EqualTo(0), "Key ring was not deleted");
            }
        }
    }
}
