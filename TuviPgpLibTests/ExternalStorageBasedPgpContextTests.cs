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

using NUnit.Framework;

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

    public class ExternalStorageBasedPgpContextTests
    {
        private static async Task<ExternalStorageBasedPgpContext> InitializeTestPgpContextAsync()
        {
            var keyStorage = new MockPgpKeyStorage().Get();
            var context = new TestPgpContext(keyStorage);
            await context.LoadContextAsync().ConfigureAwait(false);
            return context;
        }

        [Test]
        public async Task ImportPgpPublicKeyRingAsync()
        {
            PgpPublicKeyRing testKeyRing;

            using (var ctx = await InitializeTestPgpContextAsync().ConfigureAwait(false))
            {
                ctx.GenerateKeyPair(TestData.GetAccount().GetMailbox(), "");
                testKeyRing = ctx.EnumeratePublicKeyRings().First();
            }

            using var anotherCtx = await InitializeTestPgpContextAsync().ConfigureAwait(false);
            Assert.That(anotherCtx.EnumeratePublicKeyRings().Count(), Is.EqualTo(0), "Initialized context is not empty");

            anotherCtx.Import(testKeyRing);
            Assert.That(anotherCtx.EnumeratePublicKeyRings().Count(), Is.EqualTo(1), "Key ring was not imported");
            Assert.That(anotherCtx.EnumeratePublicKeyRings().First(), Is.EqualTo(testKeyRing), "Imported keyring is corrupted");
        }

        [Test]
        public async Task ImportPgpPublicKeyRingBundleAsync()
        {
            PgpPublicKeyRing testKeyRing;

            using (var ctx = await InitializeTestPgpContextAsync().ConfigureAwait(false))
            {
                ctx.GenerateKeyPair(TestData.GetAccount().GetMailbox(), "");
                testKeyRing = ctx.EnumeratePublicKeyRings().First();
            }

            using var anotherCtx = await InitializeTestPgpContextAsync().ConfigureAwait(false);
            Assert.That(anotherCtx.EnumeratePublicKeyRings().Count(), Is.EqualTo(0), "Initialized context is not empty");

            var keyRingBundle = PgpPublicKeyRingBundle.AddPublicKeyRing(new PgpPublicKeyRingBundle(Array.Empty<byte>()), testKeyRing);

            anotherCtx.Import(keyRingBundle);
            Assert.That(anotherCtx.EnumeratePublicKeyRings().Count(), Is.EqualTo(1), "Key ring bundle was not imported");
            Assert.That(anotherCtx.EnumeratePublicKeyRings().First(), Is.EqualTo(testKeyRing), "Imported keyring is corrupted");
        }

        [Test]
        public async Task ImportTwoPgpPublicKeyRingBundles()
        {
            PgpPublicKeyRing testKeyRing1;
            PgpPublicKeyRing testKeyRing2;

            using (var ctx1 = await InitializeTestPgpContextAsync().ConfigureAwait(false))
            {
                ctx1.GenerateKeyPair(TestData.GetAccount().GetMailbox(), "");
                testKeyRing1 = ctx1.EnumeratePublicKeyRings().First();
            }

            using (var ctx2 = await InitializeTestPgpContextAsync().ConfigureAwait(false))
            {
                ctx2.GenerateKeyPair(TestData.GetSecondAccount().GetMailbox(), "");
                testKeyRing2 = ctx2.EnumeratePublicKeyRings().First();
            }

            using var importingCtx = await InitializeTestPgpContextAsync().ConfigureAwait(false);
            Assert.That(importingCtx.EnumeratePublicKeyRings().Count(), Is.EqualTo(0), "Initialized context is not empty");

            var keyRingBundle1 = PgpPublicKeyRingBundle.AddPublicKeyRing(new PgpPublicKeyRingBundle(Array.Empty<byte>()), testKeyRing1);
            var keyRingBundle2 = PgpPublicKeyRingBundle.AddPublicKeyRing(new PgpPublicKeyRingBundle(Array.Empty<byte>()), testKeyRing2);
            importingCtx.Import(keyRingBundle1);
            importingCtx.Import(keyRingBundle2);

            Assert.That(importingCtx.EnumeratePublicKeyRings().Count(), Is.EqualTo(2), "Key ring bundle was not imported");
            Assert.That(importingCtx.EnumeratePublicKeyRings(), Does.Contain(testKeyRing1));
            Assert.That(importingCtx.EnumeratePublicKeyRings(), Does.Contain(testKeyRing2));
        }

        [Test]
        public async Task ImportDoublePgpPublicKeyRingBundleAsync()
        {
            PgpPublicKeyRing testKeyRing1;
            PgpPublicKeyRing testKeyRing2;

            using (var ctx = await InitializeTestPgpContextAsync().ConfigureAwait(false))
            {
                ctx.GenerateKeyPair(TestData.GetAccount().GetMailbox(), "");
                ctx.GenerateKeyPair(TestData.GetSecondAccount().GetMailbox(), "");
                testKeyRing1 = ctx.EnumeratePublicKeyRings().First(); 
                testKeyRing2 = ctx.EnumeratePublicKeyRings().Last();
            }

            using var importingCtx = await InitializeTestPgpContextAsync().ConfigureAwait(false);
            Assert.That(importingCtx.EnumeratePublicKeyRings().Count(), Is.EqualTo(0), "Initialized context is not empty");

            var keyRingBundle = PgpPublicKeyRingBundle.AddPublicKeyRing(new PgpPublicKeyRingBundle(Array.Empty<byte>()), testKeyRing1);
            keyRingBundle = PgpPublicKeyRingBundle.AddPublicKeyRing(keyRingBundle, testKeyRing2);
            importingCtx.Import(keyRingBundle);
            
            Assert.That(importingCtx.EnumeratePublicKeyRings().Count(), Is.EqualTo(2), "Key ring bundle was not imported");
            Assert.That(importingCtx.EnumeratePublicKeyRings(), Does.Contain(testKeyRing1));
            Assert.That(importingCtx.EnumeratePublicKeyRings(), Does.Contain(testKeyRing2));
        }

        [Test]
        public async Task ImportPgpSecretKeyRingAsync()
        {
            PgpSecretKeyRing testKeyRing;

            using (var ctx = await InitializeTestPgpContextAsync().ConfigureAwait(false))
            {
                ctx.GenerateKeyPair(TestData.GetAccount().GetMailbox(), "");
                testKeyRing = ctx.EnumerateSecretKeyRings().First();
            }

            using var anotherCtx = await InitializeTestPgpContextAsync().ConfigureAwait(false);
            Assert.That(anotherCtx.EnumerateSecretKeyRings().Count(), Is.EqualTo(0), "Initialized context is not empty");

            anotherCtx.Import(testKeyRing);
            Assert.That(anotherCtx.EnumerateSecretKeyRings().Count(), Is.EqualTo(1), "Key ring was not imported");
            Assert.That(anotherCtx.EnumerateSecretKeyRings().First(), Is.EqualTo(testKeyRing), "Imported keyring is corrupted");
        }

        [Test]
        public async Task ImportPgpSecretKeyRingBundleAsync()
        {
            PgpSecretKeyRing testKeyRing;

            using (var ctx = await InitializeTestPgpContextAsync().ConfigureAwait(false))
            {
                ctx.GenerateKeyPair(TestData.GetAccount().GetMailbox(), "");
                testKeyRing = ctx.EnumerateSecretKeyRings().First();
            }

            using var anotherCtx = await InitializeTestPgpContextAsync().ConfigureAwait(false);
            Assert.That(anotherCtx.EnumerateSecretKeyRings().Count(), Is.EqualTo(0), "Initialized context is not empty");

            var keyRingBundle = PgpSecretKeyRingBundle.AddSecretKeyRing(new PgpSecretKeyRingBundle(Array.Empty<byte>()), testKeyRing);

            anotherCtx.Import(keyRingBundle);
            Assert.That(anotherCtx.EnumerateSecretKeyRings().Count(), Is.EqualTo(1), "Key ring bundle was not imported");
            Assert.That(anotherCtx.EnumerateSecretKeyRings().First(), Is.EqualTo(testKeyRing), "Imported keyring is corrupted");
        }

        [Test]
        public async Task ImportTwoPgpSecretKeyRingBundlesAsync()
        {
            PgpSecretKeyRing testKeyRing1;
            PgpSecretKeyRing testKeyRing2;

            using (var ctx1 = await InitializeTestPgpContextAsync().ConfigureAwait(false))
            {
                ctx1.GenerateKeyPair(TestData.GetAccount().GetMailbox(), "");
                testKeyRing1 = ctx1.EnumerateSecretKeyRings().First();
            }

            using (var ctx2 = await InitializeTestPgpContextAsync().ConfigureAwait(false))
            {
                ctx2.GenerateKeyPair(TestData.GetSecondAccount().GetMailbox(), "");
                testKeyRing2 = ctx2.EnumerateSecretKeyRings().First();
            }

            using var importingCtx = await InitializeTestPgpContextAsync().ConfigureAwait(false);
            Assert.That(importingCtx.EnumerateSecretKeyRings().Count(), Is.EqualTo(0), "Initialized context is not empty");

            var keyRingBundle1 = PgpSecretKeyRingBundle.AddSecretKeyRing(new PgpSecretKeyRingBundle(Array.Empty<byte>()), testKeyRing1);
            var keyRingBundle2 = PgpSecretKeyRingBundle.AddSecretKeyRing(new PgpSecretKeyRingBundle(Array.Empty<byte>()), testKeyRing2);
            importingCtx.Import(keyRingBundle1);
            importingCtx.Import(keyRingBundle2);

            Assert.That(importingCtx.EnumerateSecretKeyRings().Count(), Is.EqualTo(2), "Key ring bundle was not imported");
            Assert.That(importingCtx.EnumerateSecretKeyRings(), Does.Contain(testKeyRing1));
            Assert.That(importingCtx.EnumerateSecretKeyRings(), Does.Contain(testKeyRing2));
        }

        [Test]
        public async Task ImportDoublePgpSecretKeyRingBundleAsync()
        {
            PgpSecretKeyRing testKeyRing1;
            PgpSecretKeyRing testKeyRing2;

            using (var ctx = await InitializeTestPgpContextAsync().ConfigureAwait(false))
            {
                ctx.GenerateKeyPair(TestData.GetAccount().GetMailbox(), "");                
                ctx.GenerateKeyPair(TestData.GetSecondAccount().GetMailbox(), "");
                testKeyRing1 = ctx.EnumerateSecretKeyRings().First();
                testKeyRing2 = ctx.EnumerateSecretKeyRings().Last();
            }

            using var importingCtx = await InitializeTestPgpContextAsync().ConfigureAwait(false);
            Assert.That(importingCtx.EnumerateSecretKeyRings().Count(), Is.EqualTo(0), "Initialized context is not empty");

            var keyRingBundle = PgpSecretKeyRingBundle.AddSecretKeyRing(new PgpSecretKeyRingBundle(Array.Empty<byte>()), testKeyRing1);
            keyRingBundle = PgpSecretKeyRingBundle.AddSecretKeyRing(keyRingBundle, testKeyRing2);
            importingCtx.Import(keyRingBundle);

            Assert.That(importingCtx.EnumerateSecretKeyRings().Count(), Is.EqualTo(2), "Key ring bundle was not imported");
            Assert.That(importingCtx.EnumerateSecretKeyRings(), Does.Contain(testKeyRing1));
            Assert.That(importingCtx.EnumerateSecretKeyRings(), Does.Contain(testKeyRing2));
        }

        [Test]
        public async Task DeletePgpPublicKeyRingAsync()
        {
            using var ctx = await InitializeTestPgpContextAsync().ConfigureAwait(false);
            ctx.GenerateKeyPair(TestData.GetAccount().GetMailbox(), "");
            
            Assert.That(ctx.EnumeratePublicKeyRings().Count(), Is.EqualTo(1), "Initialized context is empty");
            
            ctx.Delete(ctx.EnumeratePublicKeyRings().First());
            Assert.That(ctx.EnumeratePublicKeyRings().Count(), Is.EqualTo(0), "Key ring was not deleted");
        }

        [Test]
        public async Task DeletePgpPublicKeyRing2Async()
        {
            using var ctx = await InitializeTestPgpContextAsync().ConfigureAwait(false);
            ctx.GenerateKeyPair(TestData.GetAccount().GetMailbox(), "");
            Assert.That(ctx.EnumeratePublicKeyRings().Count(), Is.EqualTo(1), "Initialized context is empty");
            PgpPublicKeyRing keyRing = ctx.EnumeratePublicKeyRings().First();

            ctx.GenerateKeyPair(TestData.GetSecondAccount().GetMailbox(), "");
            Assert.That(ctx.EnumeratePublicKeyRings().Count(), Is.EqualTo(2), "New key ring wasn't added");
            ctx.GenerateKeyPair(TestData.GetThirdAccount().GetMailbox(), "");
            Assert.That(ctx.EnumeratePublicKeyRings().Count(), Is.EqualTo(3), "New key ring wasn't added");

            Assert.That(ctx.EnumeratePublicKeyRings(), Does.Contain(keyRing), "Needed key ring does not exist");
            ctx.Delete(keyRing);
            Assert.That(ctx.EnumeratePublicKeyRings().Contains(keyRing), Is.False);
        }

        [Test]
        public async Task DeletePgpSecretKeyRingAsync()
        {
            using var ctx = await InitializeTestPgpContextAsync().ConfigureAwait(false);
            ctx.GenerateKeyPair(TestData.GetAccount().GetMailbox(), "");

            Assert.That(ctx.EnumerateSecretKeyRings().Count(), Is.EqualTo(1), "Initialized context is empty");

            ctx.Delete(ctx.EnumerateSecretKeyRings().First());
            Assert.That(ctx.EnumerateSecretKeyRings().Count(), Is.EqualTo(0), "Key ring was not deleted");
        }

        [Test]
        public async Task DeletePgpSecretKeyRing2Async()
        {
            using var ctx = await InitializeTestPgpContextAsync().ConfigureAwait(false);
            ctx.GenerateKeyPair(TestData.GetAccount().GetMailbox(), "");
            Assert.That(ctx.EnumerateSecretKeyRings().Count(), Is.EqualTo(1), "Initialized context is empty");
            PgpSecretKeyRing keyRing = ctx.EnumerateSecretKeyRings().First();

            ctx.GenerateKeyPair(TestData.GetSecondAccount().GetMailbox(), "");
            Assert.That(ctx.EnumerateSecretKeyRings().Count(), Is.EqualTo(2), "New key ring wasn't added");
            ctx.GenerateKeyPair(TestData.GetThirdAccount().GetMailbox(), "");
            Assert.That(ctx.EnumerateSecretKeyRings().Count(), Is.EqualTo(3), "New key ring wasn't added");

            Assert.That(ctx.EnumerateSecretKeyRings(), Does.Contain(keyRing), "Needed key ring does not exist");
            ctx.Delete(keyRing);
            Assert.That(ctx.EnumerateSecretKeyRings().Contains(keyRing), Is.False);
        }

        [Test]
        public async Task ImportPublicKeyRingNullRingThrowArgumentNullExceptionAsync()
        {
            PgpPublicKeyRing? testKeyRing = null;
            using var ctx = await InitializeTestPgpContextAsync().ConfigureAwait(false);
            Assert.Throws<ArgumentNullException>(() => ctx.Import(testKeyRing));
        }

        [Test]
        public async Task ImportSecretKeyRingNullRingThrowArgumentNullExceptionAsync()
        {
            PgpSecretKeyRing? testKeyRing = null;
            using var ctx = await InitializeTestPgpContextAsync().ConfigureAwait(false);
            Assert.Throws<ArgumentNullException>(() => ctx.Import(testKeyRing));
        }

        [Test]
        public async Task ImportPublicKeyRingBundleNullBundleThrowArgumentNullExceptionAsync()
        {
            PgpPublicKeyRingBundle? testKeyBundle = null;
            using var ctx = await InitializeTestPgpContextAsync().ConfigureAwait(false);
            Assert.Throws<ArgumentNullException>(() => ctx.Import(testKeyBundle));
        }

        [Test]
        public async Task ImportSecretKeyRingBundleNullBundleThrowArgumentNullExceptionAsync()
        {
            PgpSecretKeyRingBundle? testKeyBundle = null;
            using var ctx = await InitializeTestPgpContextAsync().ConfigureAwait(false);
            Assert.Throws<ArgumentNullException>(() => ctx.Import(testKeyBundle));
        }

        [Test]
        public async Task DeletePublicKeyRingNullRingThrowArgumentNullExceptionAsync()
        {
            PgpPublicKeyRing? testKeyRing = null;
            using var ctx = await InitializeTestPgpContextAsync().ConfigureAwait(false);
            Assert.Throws<ArgumentNullException>(() => ctx.Delete(testKeyRing));
        }

        [Test]
        public async Task DeleteSecretKeyRingNullRingThrowArgumentNullExceptionAsync()
        {
            PgpSecretKeyRing? testKeyRing = null;
            using var ctx = await InitializeTestPgpContextAsync().ConfigureAwait(false);
            Assert.Throws<ArgumentNullException>(() => ctx.Delete(testKeyRing));
        }
    }
}
