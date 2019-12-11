// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Security.Cryptography;

namespace Internal.Cryptography
{
    internal static partial class HashProviderDispenser
    {
        private sealed class CryptoApiHmacProvider : HashProvider
        {
            private readonly byte[] _key;
            private SafeHashHandle _hHash;
            private SafeProvHandle _hProv;
            private SafeKeyHandle _hKey;
            private readonly int _calgHash;
            private readonly int _providerType;

            public override int HashSizeInBytes { get; }

            internal CryptoApiHmacProvider(int providerType, int calgHash, byte[] key)
            {
                if (key == null)
                    throw new ArgumentNullException("key");
                if (!ValidKeySize(key.Length, calgHash))
                {
                    throw new ArgumentException(
                        SR.Format(
                            SR.Cryptography_InvalidKeySize));
                }
                _key = key.CloneByteArray();
                _calgHash = calgHash;
                _providerType = providerType;
                SetKey();
                int dwHashSize = 0;
                int cbHashSize = sizeof(int);
                if (!Interop.Advapi32.CryptGetHashParam(_hHash, Interop.Advapi32.CryptHashProperty.HP_HASHSIZE, out dwHashSize, ref cbHashSize, 0))
                {
                    int hr = Marshal.GetHRForLastWin32Error();
                    throw new CryptographicException(hr);
                }
                if (dwHashSize < 0)
                {
                    throw new PlatformNotSupportedException(
                        SR.Format(
                            SR.Cryptography_UnknownHashAlgorithm, providerType, calgHash));
                }
                HashSizeInBytes = dwHashSize;
            }

            private bool ValidKeySize(int keysize, int calgHash)
            {
                if (calgHash == GostConstants.CALG_GR3411_2012_512_HMAC && keysize != 64)
                {
                    return false;
                } else if (calgHash == GostConstants.CALG_GR3411_2012_256_HMAC && keysize != 32)
                {
                    return false;
                } else if (calgHash == GostConstants.CALG_GR3411_HMAC && keysize != 32)
                {
                    return false;
                }
                return true;
            }

            public override void AppendHashData(ReadOnlySpan<byte> data)
            {
                bool ret = Interop.Advapi32.CryptHashData(_hHash, data.ToArray(), data.Length, 0);
                if (!ret)
                    throw new CryptographicException(Marshal.GetLastWin32Error());
            }

            private void GetCalgsFromHMAC(int hmacAlgorithm, out int keyCalg, out int keyHashCalg)
            {
                switch (hmacAlgorithm) {
                    case GostConstants.CALG_GR3411_2012_256_HMAC:
                    case GostConstants.CALG_GR3411_HMAC:
                        keyHashCalg = GostConstants.CALG_GR3411;
                        keyCalg = GostConstants.CALG_G28147;
                        break;
                    case GostConstants.CALG_GR3411_2012_512_HMAC:
                        keyHashCalg = GostConstants.CALG_GR3411_2012_512;
                        keyCalg = GostConstants.CALG_SYMMETRIC_512;
                        break;
                    case GostConstants.CALG_MD5:
                    case GostConstants.CALG_SHA1:
                    case GostConstants.CALG_SHA256:
                    case GostConstants.CALG_SHA384:
                    case GostConstants.CALG_SHA512:
                        keyCalg = GostConstants.CALG_GENERIC_SECRET;
                        keyHashCalg = GostConstants.CALG_SHA512;
                        break;
                    default:
                        throw new PlatformNotSupportedException(
                        SR.Format(
                            SR.Cryptography_UnknownHashAlgorithm, -1, hmacAlgorithm));
                }
            }

            private void SetKey()
            {
                SafeProvHandle hProv;
                if (!Interop.Advapi32.CryptAcquireContext(out hProv, null, null, _providerType, (uint)Interop.Advapi32.CryptAcquireContextFlags.CRYPT_VERIFYCONTEXT))
                {
                    int hr = Marshal.GetHRForLastWin32Error();
                    throw new CryptographicException(hr);
                }
                int keyHashCalg;
                int keyCalg;
                GetCalgsFromHMAC(_calgHash, out keyCalg, out keyHashCalg);

                SafeHashHandle hTmpHash;
                if (!Interop.Advapi32.CryptCreateHash(hProv, keyHashCalg, SafeKeyHandle.InvalidHandle, Interop.Advapi32.CryptCreateHashFlags.None, out hTmpHash))
                {
                    int hr = Marshal.GetHRForLastWin32Error();
                    throw new CryptographicException(hr);
                }
                if (!Interop.Advapi32.CryptSetHashParam(hTmpHash, Interop.Advapi32.CryptHashProperty.HP_HASHVAL, _key ,0))
                {
                    int hr = Marshal.GetHRForLastWin32Error();
                    throw new CryptographicException(hr);
                }
                SafeKeyHandle hMacKey;
                if (!Interop.Advapi32.CryptDeriveKey(hProv, keyCalg, hTmpHash, ((_key.Length > 64 ? 64 : _key.Length ) << 19), out hMacKey))
                {
                    int hr = Marshal.GetHRForLastWin32Error();
                    throw new CryptographicException(hr);
                }
                //Create Hash with imported Key
                SafeHashHandle hMacHash;
                if (keyCalg == GostConstants.CALG_GENERIC_SECRET) {
                    if (!Interop.Advapi32.CryptCreateHash(hProv, GostConstants.CALG_HMAC, hMacKey, Interop.Advapi32.CryptCreateHashFlags.None, out hMacHash))
                    {
                        int hr = Marshal.GetHRForLastWin32Error();
                        throw new CryptographicException(hr);
                    }
                    Interop.Advapi32.HMAC_INFO hmacInfo = new Interop.Advapi32.HMAC_INFO();
                    hmacInfo.HashAlgid = _calgHash;
                    if (!Interop.Advapi32.CryptSetHashParam(hMacHash, Interop.Advapi32.CryptHashProperty.HP_HMAC_INFO, hmacInfo.ToByteArray(), 0))
                    {
                        int hr = Marshal.GetHRForLastWin32Error();
                        throw new CryptographicException(hr);
                    }
                } else {
                    if (!Interop.Advapi32.CryptCreateHash(hProv, _calgHash, hMacKey, Interop.Advapi32.CryptCreateHashFlags.None, out hMacHash))
                    {
                        int hr = Marshal.GetHRForLastWin32Error();
                        throw new CryptographicException(hr);
                    }
                }
                _hProv = hProv;
                _hKey = hMacKey;
                _hHash = hMacHash;
            }

            public override unsafe byte[] FinalizeHashAndReset()
            {
                var output = new byte[HashSizeInBytes];
                bool success = TryFinalizeHashAndReset(output, out int bytesWritten);
                Debug.Assert(success);
                Debug.Assert(bytesWritten == output.Length);
                return output;
            }

            public override bool TryFinalizeHashAndReset(Span<byte> destination, out int bytesWritten)
            {
                if (destination.Length < HashSizeInBytes)
                {
                    bytesWritten = 0;
                    return false;
                }

                int hashSize = HashSizeInBytes;
                if (!Interop.Advapi32.CryptGetHashParam(_hHash, Interop.Advapi32.CryptHashProperty.HP_HASHVAL, destination, ref hashSize, 0))
                {
                    int hr = Marshal.GetHRForLastWin32Error();
                    throw new CryptographicException(hr);
                }
                bytesWritten = hashSize;

                //reinitialize
                _hHash.Dispose();
                _hKey.Dispose();
                _hProv.Dispose();
                SetKey();
                return true;
            }

            public override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    _hHash?.Dispose();
                    _hKey?.Dispose();
                    _hProv?.Dispose();
                }
            }

            internal static byte[] EncodeSimpleBlob(byte[] ukm, byte[] encryptedKey, byte[] mac, byte[] keyParams, int algid)
            {
               byte[] ret = new byte[16
                   + GostConstants.SEANCE_VECTOR_LEN
                   + GostConstants.G28147_KEYLEN
                   + GostConstants.EXPORT_IMIT_SIZE
                   + keyParams.Length];
               int pos = 0;

               // CRYPT_SIMPLEBLOB_->CRYPT_SIMPLEBLOB_HEADER
               ret[pos] = GostConstants.SIMPLEBLOB;
               pos++;
               ret[pos] = GostConstants.CSP_CUR_BLOB_VERSION;
               pos++;

               pos += 2; // Reserved

               byte[] balgid = BitConverter.GetBytes(algid);
               Array.Copy(balgid, 0, ret, pos, 4);
               pos += 4;

               byte[] magic = BitConverter.GetBytes(GostConstants.SIMPLEBLOB_MAGIC);
               Array.Copy(magic, 0, ret, pos, 4);
               pos += 4;

               byte[] ealgid = BitConverter.GetBytes(GostConstants.CALG_G28147);
               Array.Copy(ealgid, 0, ret, pos, 4);
               pos += 4;

               // CRYPT_SIMPLEBLOB_->bSV
               Array.Copy(ukm, 0, ret, pos, GostConstants.SEANCE_VECTOR_LEN);
               pos += GostConstants.SEANCE_VECTOR_LEN;

               // CRYPT_SIMPLEBLOB_->bEncryptedKey
               Array.Copy(encryptedKey, 0, ret, pos, GostConstants.G28147_KEYLEN);
               pos += GostConstants.G28147_KEYLEN;

               // CRYPT_SIMPLEBLOB_->bMacKey
               Array.Copy(mac, 0, ret, pos, GostConstants.EXPORT_IMIT_SIZE);
               pos += GostConstants.EXPORT_IMIT_SIZE;

               // CRYPT_SIMPLEBLOB_->bEncryptionParamSet
               Array.Copy(keyParams, 0, ret, pos, keyParams.Length);
               return ret;
            }
                }

        private sealed class CryptoApiHashProvider : HashProvider
        {
            private SafeHashHandle _hHash;
            private readonly SafeProvHandle _hProv;
            private readonly int _calgHash;

            public override int HashSizeInBytes { get; }

            internal CryptoApiHashProvider(int providerType, int calgHash)
            {
                SafeProvHandle hProv;
                if (!Interop.Advapi32.CryptAcquireContext(out hProv, null, null, providerType, (uint)Interop.Advapi32.CryptAcquireContextFlags.CRYPT_VERIFYCONTEXT))
                {
                    int hr = Marshal.GetHRForLastWin32Error();
                    throw new CryptographicException(hr);
                }
                SafeHashHandle hHash;
                if (!Interop.Advapi32.CryptCreateHash(hProv, calgHash, SafeKeyHandle.InvalidHandle, (int)Interop.Advapi32.CryptCreateHashFlags.None, out hHash))
                {
                    hProv.Dispose();
                    int hr = Marshal.GetHRForLastWin32Error();
                    throw new CryptographicException(hr);
                }
                hHash.SetParent(hProv);

                int dwHashSize = 0;
                int cbHashSize = sizeof(int);
                if (!Interop.Advapi32.CryptGetHashParam(hHash, Interop.Advapi32.CryptHashProperty.HP_HASHSIZE, out dwHashSize, ref cbHashSize, 0))
                {
                    hHash.Dispose();
                    hProv.Dispose();
                    int hr = Marshal.GetHRForLastWin32Error();
                    throw new CryptographicException(hr);
                }
                if (dwHashSize < 0)
                {
                    hHash.Dispose();
                    hProv.Dispose();
                    throw new PlatformNotSupportedException(
                        SR.Format(
                            SR.Cryptography_UnknownHashAlgorithm, providerType, calgHash));
                }
                HashSizeInBytes = dwHashSize;
                _calgHash = calgHash;
                _hHash = hHash;
                _hProv = hProv;
            }

            public override void AppendHashData(ReadOnlySpan<byte> data)
            {
                bool ret = Interop.Advapi32.CryptHashData(_hHash, data.ToArray(), data.Length, 0);
                if (!ret)
                    throw new CryptographicException(Marshal.GetLastWin32Error());
            }

            public override byte[] FinalizeHashAndReset()
            {
                var hash = new byte[HashSizeInBytes];
                bool success = TryFinalizeHashAndReset(hash, out int bytesWritten);
                Debug.Assert(success);
                Debug.Assert(bytesWritten == hash.Length);
                return hash;
            }

            public override bool TryFinalizeHashAndReset(Span<byte> destination, out int bytesWritten)
            {
                int hashSize = HashSizeInBytes;
                if (!Interop.Advapi32.CryptGetHashParam(_hHash, Interop.Advapi32.CryptHashProperty.HP_HASHVAL, destination, ref hashSize, 0))
                {
                    int hr = Marshal.GetHRForLastWin32Error();
                    throw new CryptographicException(hr);
                }
                bytesWritten = hashSize;

                //reinitialize
                _hHash.Dispose();
                if (!Interop.Advapi32.CryptCreateHash(_hProv, _calgHash, SafeKeyHandle.InvalidHandle, (int)Interop.Advapi32.CryptCreateHashFlags.None, out _hHash))
                {
                    int hr = Marshal.GetHRForLastWin32Error();
                    throw new CryptographicException(hr);
                }
                return true;
            }

            public override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    _hHash?.Dispose();
                    _hProv?.Dispose();
                }
            }
        }
    }
}
