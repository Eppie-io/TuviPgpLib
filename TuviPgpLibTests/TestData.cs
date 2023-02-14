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

        public static string[] PgpPubKey = new string[] {
            "046d56e80fb311a80bc96b461ef4c4323167577dc12c82f56c90c9e46ab61ac8a223ea268e080f0d72d7db8e048d7eee27f86a4a11b77b55ac95eeaaf63ae4494a",
            "04c7543b4cccd45dbd92dbf32c7e1df972277ad65d65f2e6cf000c425f8e14bbdfadee74c2c48a2e295795fb37e39aa45274f156cb30f741119e358606f451b75e",
            "041181d2bbabf8fbd69ae9a973dc31f1b2874405bbd7792472907f48fc8d29f11b9f52cfcd7c50f96760f9d9e40bc335cee04ca7a38610448823c1c1c5296c0163"
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
