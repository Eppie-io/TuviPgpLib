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

using Moq;

namespace TuviPgpLibTests
{
    internal class MockPgpKeyStorage
    {
        private PgpPublicKeyBundle? PublicKeyStorage;
        private PgpSecretKeyBundle? SecretKeyStorage;

        private readonly Mock<IKeyStorage> MockInstance;

        public MockPgpKeyStorage()
        {
            PublicKeyStorage = null;
            SecretKeyStorage = null;

            MockInstance = new Mock<IKeyStorage>();
            MockInstance.Setup(a => a.GetPgpPublicKeysAsync(default)).ReturnsAsync(PublicKeyStorage);
            MockInstance.Setup(a => a.GetPgpSecretKeysAsync(default)).ReturnsAsync(SecretKeyStorage);
            MockInstance.Setup(a => a.SavePgpPublicKeys(It.IsAny<PgpPublicKeyBundle>()))
                                       .Callback<PgpPublicKeyBundle>((bundle) => PublicKeyStorage = bundle);
            MockInstance.Setup(a => a.SavePgpSecretKeys(It.IsAny<PgpSecretKeyBundle>()))
                                       .Callback<PgpSecretKeyBundle>((bundle) => SecretKeyStorage = bundle);
        }

        public IKeyStorage Get()
        {
            return MockInstance.Object;
        }
    }
}
