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

using KeyDerivation;
using KeyDerivationLib;
using TuviPgpLib.Entities;

namespace TuviPgpLibTests
{
    internal class TestKeyDerivationDetailsProvider : IKeyDerivationDetailsProvider
    {
        public string GetSaltPhrase()
        {
            return "Bla-bla";
        }

        public int GetSeedPhraseLength()
        {
            return 12;
        }

        public Dictionary<SpecialPgpKeyType, string> GetSpecialPgpKeyIdentities()
        {
            throw new NotImplementedException();
        }
    }

    internal static class TestData
    {
        public static readonly string[] TestSeedPhrase = {
            "abandon", "abandon", "abandon", "abandon",
            "abandon", "abandon", "abandon", "abandon",
            "abandon", "abandon", "abandon", "abandon"
        };

        public static readonly string[] TestSeedPhrase2 = {
            "abandon", "abandon", "abandon", "abandon",
            "abandon", "abandon", "abandon", "abandon",
            "abandon", "abandon", "abandon", "ability"
        };

        public static string[] GetTestSeed()
        {
            return new string[] {
                "ozone",    "drill",    "grab",
                "fiber",    "curtain",  "grace",
                "pudding",  "thank",    "cruise",
                "elder",    "eight",    "picnic"
            };
        }

        public static readonly MasterKey MasterKey = CreateMasterKey(TestSeedPhrase);
        public static readonly MasterKey MasterKey2 = CreateMasterKey(TestSeedPhrase2);

        private static MasterKey CreateMasterKey(string[] seedPhrase)
        {
            MasterKeyFactory factory = new MasterKeyFactory(new TestKeyDerivationDetailsProvider());
            factory.RestoreSeedPhrase(seedPhrase);
            return factory.GetMasterKey();
        }

        public class TestAccount
        {
            public string Name = "";
            public string Address = "";

            public MailboxAddress GetMailbox()
            {
                return new MailboxAddress(Name, Address);
            }

            public UserIdentity GetUserIdentity()
            {
                return new UserIdentity(Name, Address);
            }

            public string GetPgpIdentity()
            {
                return Address;
            }
        };

        public static TestAccount GetAccount()
        {
            return new TestAccount { Address = "test@user.net", Name = "Test User" };
        }

        public static TestAccount GetSecondAccount()
        {
            return new TestAccount { Address = "test2@user.net", Name = "Test2 User" };
        }

        public static TestAccount GetThirdAccount()
        {
            return new TestAccount { Address = "test3@user.net", Name = "Test3 User" };
        }

        public const string WrongPgpIdentity = "abra-cadabra...";

        public static string TextContent = new string("Hello elliptic curve cryptography!");
    }
}
