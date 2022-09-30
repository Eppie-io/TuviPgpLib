﻿///////////////////////////////////////////////////////////////////////////////
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

using BackupLib;
using Entities;
using MimeKit;
using MimeKit.Cryptography;
using Org.BouncyCastle.Bcpg.OpenPgp;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using TuviPgpLib;

namespace TuviPgpLibImpl
{
    public static class BackupProtectorCreator
    {
        /// <summary>
        /// Create IBackupDataProtector object.
        /// </summary>
        /// <param name="tuviPgpContext">Should implement OpenPgpContext.</param>
        /// <exception cref="IncompatibleCryptoContextException"></exception>
        public static IBackupProtector CreateBackupProtector(ITuviPgpContext tuviPgpContext)
        {
            if (tuviPgpContext is OpenPgpContext openPgpContext)
            {
                return new BackupPgpBasedProtector(openPgpContext);
            }
            else
            {
                throw new IncompatibleCryptoContextException("Not compatible pgp context provided.");
            }
        }
    }

    internal class BackupPgpBasedProtector : IBackupProtector
    {
        private readonly OpenPgpContext PgpContext;
        private readonly DigestAlgorithm PreferedDigestAlgorithm = DigestAlgorithm.Sha512;
        private string BackupKeyIdentity;

        public BackupPgpBasedProtector(OpenPgpContext pgpContext)
        {
            if (pgpContext is null)
            {
                throw new ArgumentNullException(nameof(pgpContext));
            }

            PgpContext = pgpContext;

            PgpContext.DefaultEncryptionAlgorithm = EncryptionAlgorithm.Aes256;
        }

        public void SetPgpKeyIdentity(string backupPgpKeyIdentity)
        {
            if (backupPgpKeyIdentity is null)
            {
                throw new ArgumentNullException(nameof(backupPgpKeyIdentity));
            }

            BackupKeyIdentity = backupPgpKeyIdentity;
        }

        public DataProtectionFormat GetSupportedDataProtectionFormat()
        {
            return DataProtectionFormat.PgpEncryptionWithSignature;
        }

        public async Task LockDataAsync(Stream dataToProtect, Stream protectedData, CancellationToken cancellation = default)
        {
            if (dataToProtect is null)
            {
                throw new ArgumentNullException(nameof(dataToProtect));
            }
            if (protectedData is null)
            {
                throw new ArgumentNullException(nameof(protectedData));
            }

            try
            {
                await DoLockDataAsync(dataToProtect, protectedData, cancellation).ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                throw new BackupDataProtectionException("Error protecting backup data.", exception);
            }
        }

        public async Task UnlockDataAsync(Stream protectedData, Stream unprotectedData, CancellationToken cancellation = default)
        {
            if (protectedData is null)
            {
                throw new ArgumentNullException(nameof(protectedData));
            }
            if (unprotectedData is null)
            {
                throw new ArgumentNullException(nameof(unprotectedData));
            }

            try
            {
                await DoUnlockDataAsync(protectedData, unprotectedData, cancellation).ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                throw new BackupDataProtectionException("Error unprotecting backup data.", exception);
            }
        }

        public string GetBackupKeyFingerprint()
        {
            PgpPublicKey ownerPk = GetBackupPublicKey();

            return BitConverter.ToString(ownerPk.GetFingerprint()).Replace("-", string.Empty);
        }

        public Task CreateDeatachedSignatureDataAsync(Stream dataToSign, Stream deatachedSignatureData, Stream publicKeyData, CancellationToken cancellation)
        {
            if (dataToSign is null)
            {
                throw new ArgumentNullException(nameof(dataToSign));
            }
            if (deatachedSignatureData is null)
            {
                throw new ArgumentNullException(nameof(deatachedSignatureData));
            }

            try
            {
                var publicKey = GetBackupSecretKey().PublicKey;
                publicKey.Encode(publicKeyData);

                return DoSignAsync(dataToSign, deatachedSignatureData, cancellation);
            }
            catch (Exception exception)
            {
                throw new BackupDataProtectionException("Error sign backup data.", exception);
            }            
        }

        public Task<bool> VerifySignatureAsync(Stream data, Stream deatachedSignatureData, CancellationToken cancellation)
        {
            if (data is null)
            {
                throw new ArgumentNullException(nameof(data));
            }
            if (deatachedSignatureData is null)
            {
                throw new ArgumentNullException(nameof(deatachedSignatureData));
            }

            try
            {
                return DoVerifySignatureAsync(data, deatachedSignatureData, cancellation);
            }
            catch (Exception exception)
            {
                throw new BackupDataProtectionException("Error verify signature backup data.", exception);
            }            
        }

        private async Task DoLockDataAsync(Stream dataToProtect, Stream protectedData, CancellationToken cancellation)
        {            
            PgpPublicKey ownerPk = GetBackupPublicKey();
            PgpSecretKey signerSk = GetBackupSecretKey();

            MimeEntity mimeEncodedProtectedData =
                await Task.Run(() => PgpContext.SignAndEncrypt(
                    signerSk,
                    PreferedDigestAlgorithm,
                    new List<PgpPublicKey> { ownerPk },
                    dataToProtect))
                .ConfigureAwait(false);

            await mimeEncodedProtectedData.WriteToAsync(protectedData, cancellation).ConfigureAwait(false);
        }

        private MailboxAddress CreateBackupMailboxAddress()
        {
            return new MailboxAddress(string.Empty, BackupKeyIdentity);
        }

        private PgpSecretKey GetBackupSecretKey()
        {
            var dummyMailbox = CreateBackupMailboxAddress();
            return PgpContext.GetSigningKey(dummyMailbox);
        }

        private PgpPublicKey GetBackupPublicKey()
        {
            var dummyMailbox = CreateBackupMailboxAddress();
            return PgpContext.GetPublicKeys(new List<MailboxAddress> { dummyMailbox }).First();
        }

        private async Task DoUnlockDataAsync(Stream protectedData, Stream unprotectedData, CancellationToken cancellation)
        {
            var signatures = await PgpContext.DecryptToAsync(protectedData, unprotectedData, cancellation).ConfigureAwait(false);

            var signature = signatures?.First(item => item.SignerCertificate.Email == BackupKeyIdentity);

            if (signature == null)
            {
                throw new BackupVerificationException("Backup data has no signature.");
            }

            if (!signature.Verify())
            {
                throw new BackupVerificationException("Backup data signature verification failed.");
            }
        }

        private async Task DoSignAsync(Stream data, Stream deatachedSignatureData, CancellationToken cancellation)
        {
            PgpSecretKey signerSk = GetBackupSecretKey();

            data.Position = 0;
            var deatachedSignature = await PgpContext.SignAsync(signerSk, PreferedDigestAlgorithm, data, cancellation).ConfigureAwait(false);

            await deatachedSignature.WriteToAsync(deatachedSignatureData, cancellation).ConfigureAwait(false);
        }

        private async Task<bool> DoVerifySignatureAsync(Stream data, Stream deatachedSignatureData, CancellationToken cancellation)
        {
            var signatures = await PgpContext.VerifyAsync(data, deatachedSignatureData, cancellation).ConfigureAwait(false);

            var signature = signatures?.First(item => item.SignerCertificate.Email == BackupKeyIdentity);

            if (signature == null)
            {
                throw new BackupVerificationException("Backup data has no signature.");
            }

            return signature.Verify();
        }
    }
}
