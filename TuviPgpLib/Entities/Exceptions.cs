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

using System;

namespace TuviPgpLib.Entities
{
    public class CryptoContextException : Exception
    {
        public CryptoContextException()
        {
        }

        public CryptoContextException(string message) : base(message)
        {
        }

        public CryptoContextException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }

    public class ExportPublicKeyException : CryptoContextException
    {
        public ExportPublicKeyException()
        {
        }

        public ExportPublicKeyException(string message) : base(message)
        {
        }

        public ExportPublicKeyException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }

    public class ImportPublicKeyException : CryptoContextException
    {
        public ImportPublicKeyException()
        {
        }

        public ImportPublicKeyException(string message) : base(message)
        {
        }

        public ImportPublicKeyException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }

    public class UnknownPublicKeyAlgorithmException : ImportPublicKeyException
    {
        public UnknownPublicKeyAlgorithmException()
        {
        }

        public UnknownPublicKeyAlgorithmException(string message) : base(message)
        {
        }

        public UnknownPublicKeyAlgorithmException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }

    public class PublicKeyAlreadyExistException : ImportPublicKeyException
    {
        public PublicKeyAlreadyExistException()
        {
        }

        public PublicKeyAlreadyExistException(string message) : base(message)
        {
        }

        public PublicKeyAlreadyExistException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }

    public class IncompatibleCryptoContextException : CryptoContextException
    {
        public IncompatibleCryptoContextException()
        {
        }

        public IncompatibleCryptoContextException(string message) : base(message)
        {
        }

        public IncompatibleCryptoContextException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}