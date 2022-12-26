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

using TuviPgpLib.Entities;

namespace TuviPgpLibTests
{
    internal static class TestData
    {
        public static string[] GetTestSeed()
        {
            return new string[] {
                "ozone",    "drill",    "grab",
                "fiber",    "curtain",  "grace",
                "pudding",  "thank",    "cruise",
                "elder",    "eight",    "picnic"
            };
        }

        public static List<KeyValuePair<string, bool>> GetDictionaryTestData()
        {
            return new List<KeyValuePair<string, bool>>()
            {
                new KeyValuePair<string, bool>("hello", true),
                new KeyValuePair<string, bool>("shine", true),
                new KeyValuePair<string, bool>("abracadabra", false),
                new KeyValuePair<string, bool>("fakdfbmsp", false)
            };
        }

        public static string PublicKeyPath = "./key.pub";
        public static string PrivateKeyPath = "./key.priv";

        public static readonly MasterKey MasterKey = new MasterKey
        {
            Scalar = new byte[32]
            {
                0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x1A, 0x1B, 0x1C, 0x1D, 0x1F, 0x20, 0x21, 0x22,
                0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x1A, 0x1B, 0x1C, 0x1D, 0x1F, 0x20, 0x21, 0x22
            },
            ChainCode = new byte[32]
            {
                0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x1A, 0x1B, 0x1C, 0x1D, 0x1F, 0x20, 0x21, 0x22,
                0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x1A, 0x1B, 0x1C, 0x1D, 0x1F, 0x20, 0x21, 0x22
            }
        };

        public static readonly MasterKey MasterKey2 = new MasterKey
        {
            Scalar = new byte[32]
            {
                0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x1A, 0x1B, 0x1C, 0x1D, 0x1F, 0x20, 0x21, 0x22,
                0x12, 0x34, 0x56, 0x78, 0x90, 0x44, 0x77, 0xEF, 0x1A, 0x1B, 0x1C, 0x1D, 0x1F, 0x20, 0x21, 0x22
            },
            ChainCode = new byte[32]
            {
                0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0x81, 0xEF, 0x1A, 0x1B, 0x1C, 0x1D, 0x1F, 0x20, 0x21, 0x22,
                0x12, 0x34, 0x56, 0x78, 0x49, 0xAB, 0xCD, 0xEF, 0x1A, 0x1B, 0x1C, 0x1D, 0x1F, 0x20, 0x21, 0x22
            }
        };

        public static KeyValuePair<string, string>[] EccKeyPairs = new KeyValuePair<string, string>[3]
        {
             new KeyValuePair<string, string> (
                "59fc974660581e485c90d64823014433d1f9e8b38be84ab54672bbc6a0f10f12",
                "04272400c48da9668372f36fa6a165136c0e5a7f443f6f4e8d0106c49a84c40c171122013462ca687804adbb81d7e6d97ee325b5c4a02440b66089abd5d77ac8ad"),
            new KeyValuePair<string, string> (
                "5d0cb96494a800348babd8b4c82fa749f0414e03463f9b90bd321c6812777186",
                "04539c2998c1ebbf3c44703e5dd51494810774f9ae2c7342c302e0198f7bd02ede63026ffd98a5d316b608db92cbe7a8f36635406380ddc3d2c1a2f8e5ca8bfd12"),
            new KeyValuePair<string, string> (
                "efc2b56883bb15f947992e1e80aff666756c9979db07ad3b15631922bf71b5f8",
                "04b93842526c230a946c086607569ced02d6233d51ba47604e80253d032d570705d61f7d9cb985cec58ff52855cfa8bf59b9814c2299f6d4a7a62587ea06887590"),        
        };

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
