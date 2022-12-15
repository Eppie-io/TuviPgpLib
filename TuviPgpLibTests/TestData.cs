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
using MimeKit;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Mail;
using System.Text;
using System.Threading.Tasks;
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

        //public static readonly PrivateKey AccountKey1 = new MasterKey
        //{
        //    Scalar = new byte[32]
        //    {
        //        0x07, 0x77, 0x88, 0x11, 0x2d, 0xab, 0x13, 0x54, 0x0e, 0xbb, 0x67, 0x82, 0xb0, 0x60, 0x34, 0x73,
        //        0xa5, 0x6b, 0xfa, 0x5e, 0xd5, 0xf9, 0xd4, 0xd9, 0x68, 0xf8, 0x59, 0x58, 0x3c, 0x87, 0xf4, 0x57
        //    },
        //    ChainCode = new byte[32]
        //    {
        //        0xed, 0x34, 0x56, 0xc1, 0xb5, 0xfe, 0xb9, 0xe8, 0xb4, 0xe2, 0x6d, 0xd3, 0x3c, 0x27, 0xe1, 0xa9,
        //        0xdc, 0xdc, 0x80, 0xbf, 0xd2, 0x82, 0xc6, 0xb9, 0x91, 0x44, 0x9a, 0x2e, 0x31, 0x7b, 0x50, 0x56
        //    }
        //};

        //public static readonly PrivateKey AccountKey2 = new MasterKey
        //{
        //    Scalar = new byte[32]
        //    {
        //        0xef, 0x45, 0x70, 0x40, 0xe2, 0x1f, 0x14, 0x68, 0x51, 0x0f, 0x1a, 0x3f, 0x18, 0xba, 0x40, 0x27,
        //        0x2d, 0x72, 0x0f, 0xf1, 0x26, 0x16, 0x55, 0xd3, 0x21, 0xfe, 0x6c, 0x12, 0xd7, 0x55, 0x9e, 0xba
        //    },
        //    ChainCode = new byte[32]
        //    {
        //        0x73, 0x8a, 0x98, 0x02, 0x0d, 0x3e, 0xb0, 0x69, 0xcd, 0x64, 0xa2, 0x89, 0x4b, 0xbf, 0x6a, 0xdf,
        //        0xfd, 0x5b, 0xdf, 0xf0, 0xac, 0x3b, 0xb7, 0xa7, 0x59, 0x32, 0x1a, 0x60, 0x5e, 0x0f, 0x83, 0x7a
        //    }
        //};

        //public static readonly byte[] ChildKey1 = new byte[32]
        //{
        //    0x91, 0xeb, 0xc7, 0xfb, 0x74, 0xac, 0xd5, 0x23, 0x5b, 0xb5, 0xf0, 0x67, 0xfa, 0x77, 0xe4, 0x15,
        //    0x15, 0x4d, 0xe4, 0x7e, 0x95, 0x66, 0x3c, 0x28, 0x59, 0x14, 0xc0, 0xe8, 0x0b, 0x2d, 0xb3, 0x18
        //};

        //public static readonly byte[] ChildKey2 = new byte[32]
        //{
        //    0xfc, 0x89, 0x17, 0x64, 0xd3, 0x9e, 0x94, 0x5c, 0x02, 0x6f, 0xa6, 0xc3, 0x29, 0x0f, 0x09, 0xa0,
        //    0x28, 0x1b, 0xb1, 0x77, 0x59, 0xaa, 0xf5, 0x08, 0x83, 0xdc, 0x42, 0xbd, 0x54, 0x10, 0x7e, 0x12
        //};

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
        
            //new KeyValuePair<string, string> (
            //    "91ebc7fb74acd5235bb5f067fa77e415154de47e95663c285914c0e80b2db318",
            //    "045015a875711c5e1a0d51d5f666cb786e187e710a50094359a092905231de2b02eb8e5333ebaedd7e661296bec518da050f997ad4c980036145200633e3dfe685"),
            //new KeyValuePair<string, string> (
            //    "fc891764d39e945c026fa6c3290f09a0281bb17759aaf50883dc42bd54107e12",
            //    "040303493edc316f9a3934a63bd7a25ed096b5bd83bbe33c4b6b758135871a00bfabc9681b4bcac2ca9e16e1bccb3820a56780a7c4ac723ffb332e5ee0211ac980"),
            //new KeyValuePair<string, string> (
            //    "760167e64d99842e072c478372a6d0747c3a7dbe43c555d4a87ec105932d79e3",
            //    "04e8e3c49125d581bacb90614ee4b845afc9bfda4803c6e529b51e3a91d5e1c3031c7701f7a317da211ee095e82621a7da3dec774d58d057066f1e32a5c12f3d90"),
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
            //return new TestAccount { Address = "ivan@ivanov.net", Name = "Ivan Ivanov" };
            return new TestAccount { Address = "test@user.net", Name = "Test User" };
        }

        public static readonly string WrongPgpIdentity = "abra-cadabra...";

        public static string TextContent = new string("Hello elliptic curve cryptography!");
    }
}
