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

using System.Linq;

namespace TuviPgpLib.Entities
{
    public class PgpPublicKeyBundle : PgpKeyBundle
    {
    }

    public class PgpSecretKeyBundle : PgpKeyBundle
    {
    }

    public class PgpKeyBundle
    {
#pragma warning disable CA1819 // Properties should not return arrays
        public byte[] Data { get; set; }
#pragma warning restore CA1819 // Properties should not return arrays

        public override bool Equals(object obj)
        {
            if (obj is PgpKeyBundle other)
            {
                if ((Data == null && other.Data == null) ||
                     Data.SequenceEqual(other.Data))
                {
                    return true;
                }
                return false;
            }
            else
            {
                return false;
            }
        }

        public override int GetHashCode()
        {
            return base.GetHashCode();
        }
    }
}
