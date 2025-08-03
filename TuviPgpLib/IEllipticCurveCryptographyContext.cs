///////////////////////////////////////////////////////////////////////////////
//   Copyright 2025 Eppie (https://eppie.io)
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
        /// Derives a PGP key pair based on the provided master key and tag, associating it with the specified user identity.
        /// Generates a master key and subkey for encryption using elliptic curve cryptography (ECC) on the secp256k1 curve.
        /// The generated keys are imported into the current context.
        /// </summary>
        /// <param name="masterKey">The master key used for key derivation. Must not be null.</param>
        /// <param name="userIdentity">The user identity (e.g., email address) associated with the keys in the PGP key ring. Not used in key derivation. Must not be null.</param>
        /// <param name="tag">The string tag used to customize key derivation. Must not be null.</param>
        /// <exception cref="ArgumentNullException">Thrown if any parameter is null.</exception>
        /// <remarks>
        /// This method deterministically derives a master key, along with an encryption subkey, all from a single derivation key,
        /// using a tag-based key derivation scheme. These three keys form a unified PGP key hierarchy.
        /// The <paramref name="userIdentity"/> parameter is used solely to assign the identity in the PGP key ring and does not influence key derivation.
        /// Key derivation is performed using the secp256k1 elliptic curve.
        /// </remarks>
        void GeneratePgpKeysByTag(MasterKey masterKey, string userIdentity, string tag);

        /// <summary>
        /// Derives a PGP key pair using BIP44 hierarchical deterministic key derivation and associates it with the user identity.
        /// Generates ECC keys (secp256k1) for a master key and encryption subkey using the path m/44'/coin'/account'/channel/index.
        /// Imports the keys into the PGP key ring.
        /// </summary>
        /// <param name="masterKey">The master key for BIP44 derivation.</param>
        /// <param name="userIdentity">The user identity (e.g., email) associated with the PGP key ring, not used in derivation.</param>
        /// <param name="coin">Hardened coin type (SLIP-44) for derivation. Must be non-negative.</param>
        /// <param name="account">Hardened account index for derivation. Must be non-negative.</param>        
        /// <param name="channel">Non-hardened channel type (e.g., 10 for mail). Must be non-negative.</param>
        /// <param name="index">Non-hardened address index. Must be non-negative.</param>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="masterKey"/> or <paramref name="userIdentity"/> is null.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="account"/>, <paramref name="channel"/>, or <paramref name="index"/> is negative.</exception>
        // <remarks>
        /// This method deterministically derives a master key, along with an encryption subkey, all from a single derivation key,
        /// using a BIP44 key derivation scheme. These three keys form a unified PGP key hierarchy.
        /// The derivation path follows BIP44: m/44'/coin'/account'/channel/index. 
        /// The <paramref name="userIdentity"/> parameter is used solely to assign the identity in the PGP key ring and does not influence key derivation.
        /// Key derivation is performed using the secp256k1 elliptic curve.
        /// </remarks>
        void GeneratePgpKeysByBip44(MasterKey masterKey, string userIdentity, int coin, int account, int channel, int index);


        /// <summary>
        /// Derives a PGP key pair based on the provided master key and tag, associating it with the specified user identity.
        /// Generates a master key and encryption subkey using elliptic curve cryptography (ECC) on the secp256k1 curve.
        /// The generated keys are imported into the current context.
        /// </summary>
        /// <param name="masterKey">The master key used for key derivation. Must not be null.</param>
        /// <param name="userIdentity">The user identity (e.g., email address) associated with the keys in the PGP key ring. Not used in key derivation. Must not be null.</param>
        /// <param name="tag">The string tag used to customize key derivation. Must not be null.</param>
        /// <exception cref="ArgumentNullException">Thrown if any parameter is null.</exception>
        /// This method deterministically derives unique keys: a master key, along with an encryption subkey,
        /// using a tag-based key derivation scheme. These three keys form a unified PGP key hierarchy.
        /// The <paramref name="userIdentity"/> parameter is used solely to assign the identity in the PGP key ring and does not influence key derivation.
        /// Key derivation is performed using the secp256k1 elliptic curve.
        /// </remarks>
        void GeneratePgpKeysByTagOld(MasterKey masterKey, string userIdentity, string tag);
    }
}
