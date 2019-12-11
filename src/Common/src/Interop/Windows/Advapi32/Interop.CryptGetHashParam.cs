// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

internal partial class Interop
{
    internal partial class Advapi32
    {
        internal enum CryptHashProperty : int
        {
            HP_ALGID = 0x0001,  // Hash algorithm
            HP_HASHVAL = 0x0002,  // Hash value
            HP_HASHSIZE = 0x0004,  // Hash value size
            HP_HMAC_INFO = 0x0005,  // information for creating an HMAC
            HP_TLS1PRF_LABEL = 0x0006,  // label for TLS1 PRF
            HP_TLS1PRF_SEED = 0x0007,  // seed for TLS1 PRF
            HP_HASHSTARTVECT = 0x0008,  // GOST imit
        }

        [DllImport(Libraries.Advapi32, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CryptGetHashParam(
            SafeHashHandle hHash,
            CryptHashProperty dwParam,
            out int pbData,
            [In, Out] ref int pdwDataLen,
            int dwFlags);

        [DllImport(Libraries.Advapi32, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CryptGetHashParam(
            SafeHashHandle hHash,
            CryptHashProperty dwParam,
            IntPtr pbData,
            [In, Out] ref int pdwDataLen,
            int dwFlags);

        public static bool CryptGetHashParam(
            SafeHashHandle safeHashHandle,
            CryptHashProperty dwParam,
            Span<byte> pbData,
            [In, Out] ref int pdwDataLen,
            int dwFlags)
        {
            if (pbData.IsEmpty)
            {
                return CryptGetHashParam(safeHashHandle, dwParam, IntPtr.Zero, ref pdwDataLen, 0);
            }

            if (pdwDataLen > pbData.Length)
            {
                throw new IndexOutOfRangeException();
            }

            unsafe
            {
                fixed (byte* bytePtr = &MemoryMarshal.GetReference(pbData))
                {
                    return CryptGetHashParam(safeHashHandle, dwParam, (IntPtr)bytePtr, ref pdwDataLen, 0);
                }
            }
        }
        /* structure for use with CryptSetHashParam with CALG_HMAC*/
        [StructLayout(LayoutKind.Sequential)]
        public struct HMAC_INFO {
            public int      HashAlgid;
            public IntPtr   pbInnerString;
            public uint   cbInnerString;
            public IntPtr   pbOuterString;
            public uint   cbOuterString;
            //We use only HashAlgid, so all other fields can be set to zerro
            internal unsafe byte[] ToByteArray()
            {
                int numBytes = 3*sizeof(int) + 2*sizeof(IntPtr);
                byte[] data = new byte[numBytes];
                BitConverter.GetBytes(HashAlgid).CopyTo(data, 0);
                return data;
            }
        }

        [DllImport(Libraries.Advapi32, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CryptSetHashParam(SafeHashHandle hHash, CryptHashProperty dwParam, byte[] buffer, int dwFlags);
    }
}
