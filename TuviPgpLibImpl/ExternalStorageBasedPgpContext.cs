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
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using System;
using System.Collections.Generic;
using System.IO;
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
            if (storage is null)
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

            if (publicKeys?.Data is null)
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

            if (secretKeys?.Data is null)
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
            if (keyring is null)
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
            if (keyring is null)
            {
                throw new ArgumentNullException(nameof(keyring));
            }

            SecretKeyRingBundle = PgpSecretKeyRingBundle.AddSecretKeyRing(SecretKeyRingBundle, keyring);
            SaveSecretKeyRingBundle();
        }

        public override void Import(PgpSecretKeyRingBundle bundle, CancellationToken cancellationToken = default)
        {
            if (bundle is null)
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
            if (keyring is null)
            {
                throw new ArgumentNullException(nameof(keyring));
            }

            PublicKeyRingBundle = PgpPublicKeyRingBundle.RemovePublicKeyRing(PublicKeyRingBundle, keyring);
            SavePublicKeyRingBundle();
        }

        public override void Delete(PgpSecretKeyRing keyring)
        {
            if (keyring is null)
            {
                throw new ArgumentNullException(nameof(keyring));
            }

            SecretKeyRingBundle = PgpSecretKeyRingBundle.RemoveSecretKeyRing(SecretKeyRingBundle, keyring);
            SaveSecretKeyRingBundle();
        }

        /// <summary>
        /// Imports a public key ring, merging user IDs if a key with the same KeyId already exists.
        /// </summary>
        /// <param name="keyring">The public key ring to import.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        public void ImportOrMerge(PgpPublicKeyRing keyring, CancellationToken cancellationToken = default)
        {
            if (keyring is null)
            {
                throw new ArgumentNullException(nameof(keyring));
            }

            var masterKey = keyring.GetPublicKey();
            var existingKeyRing = TryGetExistingPublicKeyRing(masterKey.KeyId);

            if (existingKeyRing != null)
            {
                // Key with this KeyId already exists - merge user IDs from new keyring into existing one
                var mergedKeyRing = MergePublicKeyRings(existingKeyRing, keyring);

                // Remove old keyring and add merged one
                PublicKeyRingBundle = PgpPublicKeyRingBundle.RemovePublicKeyRing(PublicKeyRingBundle, existingKeyRing);
                PublicKeyRingBundle = PgpPublicKeyRingBundle.AddPublicKeyRing(PublicKeyRingBundle, mergedKeyRing);
            }
            else
            {
                PublicKeyRingBundle = PgpPublicKeyRingBundle.AddPublicKeyRing(PublicKeyRingBundle, keyring);
            }

            SavePublicKeyRingBundle();
        }

        /// <summary>
        /// Tries to find an existing public key ring by key ID.
        /// </summary>
        /// <returns>
        /// The <see cref="PgpPublicKeyRing"/> if found; otherwise, <c>null</c> if no key ring is found for the given key ID.
        /// </returns>
        private PgpPublicKeyRing TryGetExistingPublicKeyRing(long keyId)
        {
            try
            {
                return PublicKeyRingBundle.GetPublicKeyRing(keyId);
            }
            catch (PgpException)
            {
                return null;
            }
            catch (ArgumentException)
            {
                return null;
            }
        }

        /// <summary>
        /// Merges two public key rings by combining their user IDs.
        /// Creates a new keyring with all user IDs from both keyrings.
        /// </summary>
        private static PgpPublicKeyRing MergePublicKeyRings(PgpPublicKeyRing existingKeyRing, PgpPublicKeyRing newKeyRing)
        {
            // Collect existing user IDs
            var existingMasterKey = existingKeyRing.GetPublicKey();
            var existingUserIds = new HashSet<string>();
            foreach (var userId in existingMasterKey.GetUserIds())
            {
                if (userId is string userIdString)
                {
                    existingUserIds.Add(userIdString);
                }
            }

            // Get new user IDs that don't exist
            var newMasterKey = newKeyRing.GetPublicKey();
            var newUserIds = new List<string>();
            foreach (var userId in newMasterKey.GetUserIds())
            {
                if (userId is string userIdString && !existingUserIds.Contains(userIdString))
                {
                    newUserIds.Add(userIdString);
                }
            }

            // If no new user IDs, return existing keyring
            if (newUserIds.Count == 0)
            {
                return existingKeyRing;
            }

            // Build a new keyring by encoding existing packets and adding new UserIdPackets
            using (var memoryStream = new MemoryStream())
            using (var bcpgOut = new BcpgOutputStream(memoryStream))
            {

                // Encode master public key
                existingMasterKey.PublicKeyPacket.Encode(bcpgOut);

                // Encode existing user IDs with their signatures
                foreach (var userId in existingMasterKey.GetUserIds())
                {
                    if (userId is string userIdString)
                    {
                        var userIdPacket = new UserIdPacket(userIdString);
                        userIdPacket.Encode(bcpgOut);

                        // Copy signatures for this user ID
                        var sigs = existingMasterKey.GetSignaturesForId(userIdString);
                        if (sigs != null)
                        {
                            foreach (PgpSignature sig in sigs)
                            {
                                sig.Encode(bcpgOut);
                            }
                        }
                    }
                }

                // Add new user IDs without importing any associated signatures.
                // This is intentional: our application creates and manages user IDs without signatures,
                // and any signatures present in the imported keyring for these user IDs are intentionally discarded.
                foreach (var newUserId in newUserIds)
                {
                    var userIdPacket = new UserIdPacket(newUserId);
                    userIdPacket.Encode(bcpgOut);
                }

                // Encode subkeys
                foreach (PgpPublicKey key in existingKeyRing.GetPublicKeys())
                {
                    if (key.IsMasterKey)
                    {
                        continue;
                    }

                    key.PublicKeyPacket.Encode(bcpgOut);

                    // Copy signatures for this subkey
                    var keySigs = key.GetSignatures();
                    if (keySigs != null)
                    {
                        foreach (PgpSignature sig in keySigs)
                        {
                            sig.Encode(bcpgOut);
                        }
                    }
                }

                bcpgOut.Flush();
                memoryStream.Position = 0;

                return new PgpPublicKeyRing(memoryStream);
            }
        }

    }
}
