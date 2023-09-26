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

namespace TuviPgpLib
{
    /// <summary>
    /// <see cref="MimeKit.Cryptography.OpenPgpContext"/> extension for work with Eliptic Curve Cryptography
    /// and generating keys in a deterministic way.
    /// </summary>
    public interface IEllipticCurveCryptographyPgpContext
    {
        /// <summary>
        /// Create new PGP keyring.
        /// ECC keys will be derived from <paramref name="masterKey"/> for specified <paramref name="userIdentity"/>.
        /// </summary>
        void DeriveKeyPair(MasterKey masterKey, string userIdentity);

        /// <summary>
        /// Adds new keys to the PGP key ring
        /// </summary>
        /// <param name="masterKey">Master key</param>
        /// <param name="userIdentity">User identity, it's used to search keys in the ring</param>
        /// <param name="tag">Tag, which is used for deterministic key generation</param>
        void DeriveKeyPair(MasterKey masterKey, string userIdentity, string tag);
    }
}
