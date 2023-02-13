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

using KeyDerivation.Keys;
using MimeKit.Cryptography;
using Org.BouncyCastle.Bcpg.OpenPgp;
using System;
using System.Threading;
using System.Threading.Tasks;
using TuviPgpLib;
using TuviPgpLib.Entities;

namespace TuviPgpLibImpl
{
    /// <summary>
    /// Implements support of external PGP key bundles storage using <see cref="IKeyStorage"/>.
    /// This overrides <see cref="MimeKit.Cryptography.OpenPgpContext"/>
    /// logic related to storing key bundles in files for all child classes.
    /// </summary>
    public abstract class ExternalStorageBasedPgpContext : GnuPGContext, IExternalStorageBasedPgpContext
    {
        private readonly IKeyStorage KeyStorage;

        protected ExternalStorageBasedPgpContext(IKeyStorage storage) : base()
        {
            if (storage == null)
            {
                throw new ArgumentNullException(nameof(storage), $"PGP keys storage parameter is not set.");
            }

            KeyStorage = storage;
        }

        public async Task LoadContextAsync()
        {
            await LoadPublicKeyRingBundleAsync().ConfigureAwait(false);
            await LoadSecretKeyRingBundleAsync().ConfigureAwait(false);
        }

        private async Task LoadPublicKeyRingBundleAsync()
        {
            var publicKeys = await KeyStorage.GetPgpPublicKeysAsync().ConfigureAwait(false);

            if (publicKeys?.Data == null)
            {
                PublicKeyRingBundle = CreateEmptyPgpPublicKeyRingBundle();
            }
            else
            {
                PublicKeyRingBundle = new PgpPublicKeyRingBundle(publicKeys.Data);
            }
        }

        private async Task LoadSecretKeyRingBundleAsync()
        {
            var secretKeys = await KeyStorage.GetPgpSecretKeysAsync().ConfigureAwait(false);

            if (secretKeys?.Data == null)
            {
                SecretKeyRingBundle = CreateEmptyPgpSecretKeyRingBundle();
            }
            else
            {
                SecretKeyRingBundle = new PgpSecretKeyRingBundle(secretKeys.Data);
            }
        }

        protected static PgpPublicKeyRingBundle CreateEmptyPgpPublicKeyRingBundle()
        {
            return new PgpPublicKeyRingBundle(Array.Empty<byte>());
        }

        protected static PgpSecretKeyRingBundle CreateEmptyPgpSecretKeyRingBundle()
        {
            return new PgpSecretKeyRingBundle(Array.Empty<byte>());
        }

        protected new void SavePublicKeyRingBundle()
        {
            PgpPublicKeyBundle keyBundle = new PgpPublicKeyBundle
            {
                Data = PublicKeyRingBundle.GetEncoded()
            };

            KeyStorage.SavePgpPublicKeys(keyBundle);
        }

        protected new void SaveSecretKeyRingBundle()
        {
            PgpSecretKeyBundle keyBundle = new PgpSecretKeyBundle
            {
                Data = SecretKeyRingBundle.GetEncoded()
            };

            KeyStorage.SavePgpSecretKeys(keyBundle);
        }

        public override void Import(PgpPublicKeyRing keyring, CancellationToken cancellationToken = default)
        {
            if (keyring == null)
            {
                throw new ArgumentNullException(nameof(keyring));
            }

            PublicKeyRingBundle = PgpPublicKeyRingBundle.AddPublicKeyRing(PublicKeyRingBundle, keyring);
            SavePublicKeyRingBundle();
        }

        public override void Import(PgpPublicKeyRingBundle bundle, CancellationToken cancellationToken = default)
        {
            if (bundle == null)
            {
                throw new ArgumentNullException(nameof(bundle));
            }

            int publicKeysAdded = 0;

            foreach (PgpPublicKeyRing pubring in bundle.GetKeyRings())
            {
                PublicKeyRingBundle = PgpPublicKeyRingBundle.AddPublicKeyRing(PublicKeyRingBundle, pubring);
                publicKeysAdded++;
            }

            if (publicKeysAdded > 0)
            {
                SavePublicKeyRingBundle();
            }
        }

        public override void Import(PgpSecretKeyRing keyring, CancellationToken cancellationToken = default)
        {
            if (keyring == null)
            {
                throw new ArgumentNullException(nameof(keyring));
            }

            SecretKeyRingBundle = PgpSecretKeyRingBundle.AddSecretKeyRing(SecretKeyRingBundle, keyring);
            SaveSecretKeyRingBundle();
        }

        public override void Import(PgpSecretKeyRingBundle bundle, CancellationToken cancellationToken = default)
        {
            if (bundle == null)
            {
                throw new ArgumentNullException(nameof(bundle));
            }

            int secretKeysAdded = 0;

            foreach (PgpSecretKeyRing secring in bundle.GetKeyRings())
            {
                SecretKeyRingBundle = PgpSecretKeyRingBundle.AddSecretKeyRing(SecretKeyRingBundle, secring);
                secretKeysAdded++;
            }

            if (secretKeysAdded > 0)
            {
                SaveSecretKeyRingBundle();
            }
        }

        public override void Delete(PgpPublicKeyRing keyring)
        {
            if (keyring == null)
            {
                throw new ArgumentNullException(nameof(keyring));
            }

            PublicKeyRingBundle = PgpPublicKeyRingBundle.RemovePublicKeyRing(PublicKeyRingBundle, keyring);
            SavePublicKeyRingBundle();
        }

        public override void Delete(PgpSecretKeyRing keyring)
        {
            if (keyring == null)
            {
                throw new ArgumentNullException(nameof(keyring));
            }

            SecretKeyRingBundle = PgpSecretKeyRingBundle.RemoveSecretKeyRing(SecretKeyRingBundle, keyring);
            SaveSecretKeyRingBundle();
        }
    }
}
