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

using Org.BouncyCastle.Bcpg.OpenPgp;
using System;
using System.Linq;
using TuviPgpLib.Entities;

namespace TuviPgpLibImpl
{
    public static class PgpExtensions
    {
        public static PgpKeyInfo GetMasterKeyInfo(this PgpPublicKeyRing pgpPublicKeyRing)
        {
            try
            {
                return pgpPublicKeyRing?.GetPublicKeys()
                    .Cast<PgpPublicKey>()
                    .Where(key => key.IsMasterKey)
                    .Select(key => key.CreatePgpKeyInfo())
                    .FirstOrDefault();
            }
            catch (ArgumentNullException)
            {
                return null;
            }
            catch (InvalidCastException)
            {
                return null;
            }
        }

        public static PgpKeyInfo CreatePgpKeyInfo(this PgpPublicKey key)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            return new PgpKeyInfo
            {
                KeyId = key.KeyId,
                Algorithm = key.Algorithm.ToString(),
                BitStrength = key.BitStrength,
                CreationTime = key.CreationTime,
                ValidSeconds = key.GetValidSeconds(),
                UserIdentity = key.GetUserIdentity(),
                Fingerprint = BitConverter.ToString(key.GetFingerprint()).Replace("-", string.Empty),
                IsEncryptionKey = key.IsEncryptionKey,
                IsMasterKey = key.IsMasterKey,
                IsRevoked = key.IsRevoked()
            };
        }

        public static string GetUserIdentity(this PgpPublicKey publicKey)
        {
            try
            {
                string userIdentity = publicKey?.GetUserIds().Cast<string>().FirstOrDefault();

                return userIdentity == null ? String.Empty : userIdentity;
            }
            catch (ArgumentNullException)
            {
                return String.Empty;
            }
            catch (InvalidCastException)
            {
                return String.Empty;
            }
        }
    }
}
