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

using MimeKit;
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
    public static class TuviPgpContextCreator
    {
        public static ITuviPgpContext GetPgpContext(IKeyStorage storage, IKeyMatcher keyMatcher)
        {
            return new TuviPgpContext(storage, keyMatcher);
        }
    }

    public interface IKeyMatcher
    {
        bool IsMatch(PgpPublicKey key, MailboxAddress mailbox);
    }

    public class TuviPgpContext : EccPgpContext, ITuviPgpContext
    {
        private readonly IKeyMatcher _matcher;
        public TuviPgpContext(IKeyStorage storage, IKeyMatcher keyMatcher = null) : base(storage)
        {
            _matcher = keyMatcher;
        }

        protected override string GetPasswordForKey(PgpSecretKey key)
        {
            return string.Empty;
        }

        public override IEnumerable<PgpPublicKeyRing> EnumeratePublicKeyRings(MailboxAddress mailbox)
        {
            if (mailbox == null)
                throw new ArgumentNullException(nameof(mailbox));

            foreach (var keyring in EnumeratePublicKeyRings())
            {
                var publicKey = keyring.GetPublicKey();
                if (IsMatch(publicKey, mailbox) || (_matcher != null && _matcher.IsMatch(publicKey, mailbox)))
                    yield return keyring;
            }

            yield break;
        }

        protected override PgpPublicKey GetPublicKey(MailboxAddress mailbox)
        {
            foreach (var key in EnumeratePublicKeys(mailbox))
            {
                if (!key.IsEncryptionKey || IsExpired(key))
                    continue;

                return key;
            }

            throw new PublicKeyNotFoundException(mailbox, "The public key could not be found.");
        }

        public bool IsSecretKeyExist(UserIdentity userIdentity)
        {
            if (userIdentity == null)
            {
                throw new ArgumentNullException(nameof(userIdentity));
            }

            return CanSign(new MimeKit.MailboxAddress(userIdentity.Name, userIdentity.Address));
        }

        public void ExportSecretKeys(string userIdentity, Stream outputStream, bool isArmored = false)
        {
            if (outputStream == null)
            {
                throw new ArgumentNullException(nameof(outputStream), $"Export secret key {nameof(outputStream)} is null.");
            }

            var secretKeyRings = SecretKeyRingBundle.GetKeyRings(userIdentity);
            var bundle = new PgpSecretKeyRingBundle(secretKeyRings);

            if (isArmored)
            {
                using (var armored = new ArmoredOutputStream(outputStream))
                {
                    armored.SetHeader("Version", null);

                    bundle.Encode(armored);
                    armored.Flush();
                }
            }
            else
            {
                bundle.Encode(outputStream);
            }
        }

        public void ExportPublicKeys(IEnumerable<UserIdentity> userIdentities, Stream outputStream, bool isArmored = false)
        {
            var identities = userIdentities.Select(identity => new MailboxAddress(identity.Name, identity.Address)).ToList();
            base.Export(identities, outputStream, isArmored);
        }

        public async Task ExportPublicKeyRingAsync(long keyId, Stream stream, CancellationToken cancellationToken)
        {
            try
            {
                var publicKeyRing = await base.GetPublicKeyRingAsync(keyId, cancellationToken).ConfigureAwait(false);

                cancellationToken.ThrowIfCancellationRequested();
                PgpPublicKeyRingBundle emptyBundle = CreateEmptyPgpPublicKeyRingBundle();
                PgpPublicKeyRingBundle publicKeyRingBundle = PgpPublicKeyRingBundle.AddPublicKeyRing(emptyBundle, publicKeyRing);

                cancellationToken.ThrowIfCancellationRequested();
                await base.ExportAsync(publicKeyRingBundle, stream, true, cancellationToken).ConfigureAwait(false);
            }
            catch (ArgumentNullException exception)
            {
                throw new ExportPublicKeyException(exception.Message, exception);
            }
            catch (ArgumentException exception)
            {
                throw new ExportPublicKeyException(exception.Message, exception);
            }
            catch (IOException exception)
            {
                throw new ExportPublicKeyException(exception.Message, exception);
            }
        }

        public ICollection<PgpKeyInfo> GetPublicKeysInfo()
        {
            var publicKeyRings = base.EnumeratePublicKeyRings();
            var keysInfo = new List<PgpKeyInfo>();

            foreach (var keyRing in publicKeyRings)
            {
                var masterKeyInfo = keyRing.GetMasterKeyInfo();
                if (masterKeyInfo != null)
                {
                    keysInfo.Add(masterKeyInfo);
                }
            }

            return keysInfo;
        }

        public void ImportSecretKeys(Stream inputStream, bool isArmored)
        {
            if (inputStream == null)
            {
                throw new ArgumentNullException(nameof(inputStream), $"Import secret key {nameof(inputStream)} is null.");
            }

            if (isArmored)
            {
                using (var armored = new ArmoredInputStream(inputStream))
                {
                    var bundle = new PgpSecretKeyRingBundle(armored);
                    Import(bundle);
                }
            }
            else
            {
                var bundle = new PgpSecretKeyRingBundle(inputStream);
                Import(bundle);
            }
        }

        public void ImportPublicKeys(Stream inputStream, bool isArmored)
        {
            try
            {
                if (isArmored)
                {
                    base.Import(inputStream);
                }
                else
                {
                    base.Import(new PgpPublicKeyRingBundle(inputStream));
                }
            }
            catch (ArgumentException exception)
            {
                if (exception.Message == "Bundle already contains a key with a keyId for the passed in ring.")
                {
                    throw new PublicKeyAlreadyExistException(exception.Message, exception);
                }
                else
                {
                    throw new ImportPublicKeyException(exception.Message, exception);
                }
            }
            catch (IOException exception)
            {
                if (exception.Message == "unknown PGP public key algorithm encountered")
                {
                    throw new UnknownPublicKeyAlgorithmException(exception.Message, exception);
                }
                else
                {
                    throw new ImportPublicKeyException(exception.Message, exception);
                }
            }
            catch (Exception exception)
            {
                throw new ImportPublicKeyException(exception.Message, exception);
            }
        }
    }
}
