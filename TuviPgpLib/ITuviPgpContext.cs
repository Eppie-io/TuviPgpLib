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

using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using TuviPgpLib.Entities;

namespace TuviPgpLib
{
    /// <summary>
    /// <see cref="MimeKit.Cryptography.OpenPgpContext"/> extension for work with entities
    /// and manipulating PGP keys in a handy way.
    /// </summary>
    public interface ITuviPgpContext : IEllipticCurveCryptographyPgpContext, IExternalStorageBasedPgpContext
    {
        /// <summary>
        /// Export secret PGP keyring bundle in either armored or binary formats.
        /// </summary>
        /// <param name="userIdentity">Identify which keys should be exported.</param>
        /// <param name="outputStream">Key export data stream.</param>
        /// <param name="isArmored">Specifies if keys should be exported armored or not.</param>
        void ExportSecretKeys(string userIdentity, Stream outputStream, bool isArmored = false);

        /// <summary>
        /// Export public PGP keyring bundle in either armored or binary formats.
        /// </summary>
        /// <param name="userIdentities">Identify which keys should be exported.</param>
        /// <param name="outputStream">Key export data stream.</param>
        /// <param name="isArmored">Specifies if keys should be exported armored or not.</param>
        void ExportPublicKeys(IEnumerable<UserIdentity> userIdentities, Stream outputStream, bool isArmored = false);

        /// <summary>
        /// Export armored public keyring containing public key with <paramref name="keyId"/> to <paramref name="stream"/>.
        /// </summary>
        /// <exception cref="OperationCanceledException"/>
        /// <exception cref="ExportPublicKeyException"/>
        Task ExportPublicKeyRingAsync(long keyId, Stream stream, CancellationToken cancellationToken = default);

        /// <summary>
        /// Get all public keys information.
        /// </summary>
        /// <returns>List of pulic key info</returns>
        ICollection<PgpKeyInfo> GetPublicKeysInfo();

        /// <summary>
        /// Import secret PGP keyring bundle.
        /// </summary>
        /// <param name="inputStream">Importing keys data stream.</param>
        /// <param name="isArmored">Specify if importing keys are armored or not.</param>
        void ImportSecretKeys(Stream inputStream, bool isArmored = false);

        /// <summary>
        /// Import public PGP keyring bundle.
        /// </summary>
        /// <param name="inputStream">Importing keys data stream.</param>
        /// <param name="isArmored">Specify if importing keys are armored or not.</param>
        /// <exception cref="PublicKeyAlreadyExistException"/>
        /// <exception cref="UnknownPublicKeyAlgorithmException"/>
        /// <exception cref="ImportPublicKeyException"/>
        void ImportPublicKeys(Stream inputStream, bool isArmored = true);

        /// <summary>
        /// Checks if there are any secret key for specified <paramref name="userIdentity"/>.
        /// </summary>
        bool IsSecretKeyExist(UserIdentity userIdentity);
    }
}
