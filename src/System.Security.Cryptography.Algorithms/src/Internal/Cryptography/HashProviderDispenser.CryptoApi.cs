// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Diagnostics;
using System.Security.Cryptography;

namespace Internal.Cryptography
{
    internal static partial class HashProviderDispenser
    {
        //internal static class HashAlgid
        //{
        //    internal const int MD5 = 0x8003;
        //    internal const int SHA1 = 0x8004;
        //    internal const int SHA256 = 0x800C;
        //    internal const int SHA384 = 0x800D;
        //    internal const int SHA512 = 0x800E;
        //    internal const int GOSTR3411 = 0x801E;
        //    internal const int GOST3411_2012_256 = 0x8021;
        //    internal const int GOST3411_2012_512 = 0x8022;
        //}

        //internal static class ProviderType
        //{
        //    internal const int PROV_GOST_2001_DH = 75;
        //    internal const int PROV_GOST_2012_256 = 80;
        //    internal const int PROV_GOST_2012_512 = 81;
        //}

        public static HashProvider CreateHashProvider(string hashAlgorithmId)
        {
            switch (hashAlgorithmId)
            {
                case HashAlgorithmNames.MD5:
                    return new CryptoApiHashProvider(GostConstants.PROV_GOST_2001_DH, GostConstants.CALG_MD5);
                case HashAlgorithmNames.SHA1:
                    return new CryptoApiHashProvider(GostConstants.PROV_GOST_2001_DH, GostConstants.CALG_SHA1);
                case HashAlgorithmNames.SHA256:
                    return new CryptoApiHashProvider(GostConstants.PROV_GOST_2001_DH, GostConstants.CALG_SHA256);
                case HashAlgorithmNames.SHA384:
                    return new CryptoApiHashProvider(GostConstants.PROV_GOST_2001_DH, GostConstants.CALG_SHA384);
                case HashAlgorithmNames.SHA512:
                    return new CryptoApiHashProvider(GostConstants.PROV_GOST_2001_DH, GostConstants.CALG_SHA512);
                case HashAlgorithmNames.GOST3411:
                    return new CryptoApiHashProvider(GostConstants.PROV_GOST_2001_DH, GostConstants.CALG_GR3411);
                case HashAlgorithmNames.GOST3411_2012_256:
                    return new CryptoApiHashProvider(GostConstants.PROV_GOST_2012_256, GostConstants.CALG_GR3411_2012_256);
                case HashAlgorithmNames.GOST3411_2012_512:
                    return new CryptoApiHashProvider(GostConstants.PROV_GOST_2012_512, GostConstants.CALG_GR3411_2012_512);
            }

            throw new CryptographicException(SR.Format(SR.Cryptography_UnknownHashAlgorithm, hashAlgorithmId));
        }

        public static HashProvider CreateMacProvider(string hashAlgorithmId, byte[] key)
        {
            switch (hashAlgorithmId)
            {
                case HashAlgorithmNames.MD5:
                    return new CryptoApiHmacProvider(GostConstants.PROV_GOST_2001_DH, GostConstants.CALG_MD5, key);
                case HashAlgorithmNames.SHA1:
                    return new CryptoApiHmacProvider(GostConstants.PROV_GOST_2001_DH, GostConstants.CALG_SHA1, key);
                case HashAlgorithmNames.SHA256:
                    return new CryptoApiHmacProvider(GostConstants.PROV_GOST_2001_DH, GostConstants.CALG_SHA256, key);
                case HashAlgorithmNames.SHA384:
                    return new CryptoApiHmacProvider(GostConstants.PROV_GOST_2001_DH, GostConstants.CALG_SHA384, key);
                case HashAlgorithmNames.SHA512:
                    return new CryptoApiHmacProvider(GostConstants.PROV_GOST_2001_DH, GostConstants.CALG_SHA512, key);
                case HashAlgorithmNames.GOST3411:
                    return new CryptoApiHmacProvider(GostConstants.PROV_GOST_2001_DH, GostConstants.CALG_GR3411_HMAC, key);
                case HashAlgorithmNames.GOST3411_2012_256:
                    return new CryptoApiHmacProvider(GostConstants.PROV_GOST_2012_256, GostConstants.CALG_GR3411_2012_256_HMAC, key);
                case HashAlgorithmNames.GOST3411_2012_512:
                    return new CryptoApiHmacProvider(GostConstants.PROV_GOST_2012_512, GostConstants.CALG_GR3411_2012_512_HMAC, key);
            }

            throw new CryptographicException(SR.Format(SR.Cryptography_UnknownHashAlgorithm, hashAlgorithmId));
        }

    }
}
