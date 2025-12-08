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
using System.Linq;
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
        /// <exception cref="PublicKeyAlreadyExistException">
        /// Thrown when importing a keyring with the same KeyId and identical user IDs.
        /// </exception>
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
        /// <remarks>
        /// This method assumes both key rings have the same master key and identical subkey structure.
        /// Only user IDs are merged; subkeys from <paramref name="newKeyRing"/> are intentionally ignored
        /// since they should be identical to the subkeys in <paramref name="existingKeyRing"/>.
        /// </remarks>
        /// <exception cref="PublicKeyAlreadyExistException">
        /// Thrown when the new keyring contains no new user IDs (all user IDs already exist in the existing keyring).
        /// </exception>
        private static PgpPublicKeyRing MergePublicKeyRings(PgpPublicKeyRing existingKeyRing, PgpPublicKeyRing newKeyRing)
        {
            var existingMasterKey = existingKeyRing.GetPublicKey();
            var newMasterKey = newKeyRing.GetPublicKey();

            // Validate that both keyrings have the same master key
            if (existingMasterKey.KeyId != newMasterKey.KeyId)
            {
                throw new ArgumentException(
                    $"Cannot merge key rings with different master key IDs: {existingMasterKey.KeyId} vs {newMasterKey.KeyId}",
                    nameof(newKeyRing));
            }

            var existingUserIds = new HashSet<string>(existingMasterKey.GetUserIds().OfType<string>());

            // Get new user IDs that don't exist in the existing keyring
            var newUserIds = newMasterKey.GetUserIds()
                .OfType<string>()
                .Where(userId => !existingUserIds.Contains(userId))
                .ToList();

            // If no new user IDs, throw exception - the keyring already exists with these identities
            if (newUserIds.Count == 0)
            {
                var existingIdentities = string.Join(", ", existingUserIds);
                throw new PublicKeyAlreadyExistException(
                    $"A key ring with KeyId {existingMasterKey.KeyId:X16} already exists with the same user identities: {existingIdentities}");
            }

            // Build a new keyring by encoding existing packets and adding new UserIdPackets
            using (var memoryStream = new MemoryStream())
            using (var bcpgOut = new BcpgOutputStream(memoryStream))
            {
                existingMasterKey.PublicKeyPacket.Encode(bcpgOut);

                // Encode existing user IDs with their signatures
                foreach (var userIdString in existingUserIds)
                {
                    EncodeUserId(bcpgOut, userIdString, existingMasterKey.GetSignaturesForId(userIdString)?.Cast<PgpSignature>());
                }

                // Add new user IDs without signatures (intentional - see method docs)
                foreach (var newUserId in newUserIds)
                {
                    EncodeUserId(bcpgOut, newUserId, signatures: null);
                }

                // Encode subkeys from existing keyring (subkeys should be identical in both keyrings)
                foreach (var key in existingKeyRing.GetPublicKeys().Cast<PgpPublicKey>().Where(k => !k.IsMasterKey))
                {
                    key.PublicKeyPacket.Encode(bcpgOut);

                    foreach (var sig in key.GetSignatures()?.Cast<PgpSignature>() ?? Enumerable.Empty<PgpSignature>())
                    {
                        sig.Encode(bcpgOut);
                    }
                }

                bcpgOut.Flush();
                memoryStream.Position = 0;

                return new PgpPublicKeyRing(memoryStream);
            }
        }

        /// <summary>
        /// Encodes a user ID packet and its optional signatures to the output stream.
        /// </summary>
        private static void EncodeUserId(BcpgOutputStream bcpgOut, string userId, IEnumerable<PgpSignature> signatures)
        {
            new UserIdPacket(userId).Encode(bcpgOut);

            foreach (var sig in signatures ?? Enumerable.Empty<PgpSignature>())
            {
                sig.Encode(bcpgOut);
            }
        }
    }
}
