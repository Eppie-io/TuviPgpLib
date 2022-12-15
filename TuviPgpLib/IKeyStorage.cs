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

using Entities;
using System.Threading;
using System.Threading.Tasks;

namespace TuviPgpLib
{
    /// <summary>
    /// Password protected key storage
    /// </summary>
    public interface IKeyStorage
    {
        /// <summary>
        /// Initialize <paramref name="masterKey"/>.
        /// </summary>
        /// <exception cref="DataBaseException" />
        Task InitializeMasterKeyAsync(MasterKey masterKey, CancellationToken cancellationToken = default);

        /// <summary>
        /// Check if master key is stored.
        /// </summary>
        Task<bool> IsMasterKeyExistAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Extracts stored master key.
        /// </summary>
        Task<MasterKey> GetMasterKeyAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Stores PGP public key ring bundle.
        /// </summary>
        void SavePgpPublicKeys(PgpPublicKeyBundle keyBundle);

        /// <summary>
        /// Stores PGP secret key ring bundle.
        /// </summary>
        void SavePgpSecretKeys(PgpSecretKeyBundle keyBundle);

        /// <summary>
        /// Extracts PGP public key ring bundle.
        /// </summary>
        Task<PgpPublicKeyBundle> GetPgpPublicKeysAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Extracts PGP secret key ring bundle.
        /// </summary>
        Task<PgpSecretKeyBundle> GetPgpSecretKeysAsync(CancellationToken cancellationToken = default);
    }
}
