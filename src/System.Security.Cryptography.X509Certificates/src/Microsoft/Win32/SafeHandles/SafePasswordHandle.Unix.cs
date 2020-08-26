// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace Microsoft.Win32.SafeHandles
{
    internal partial class SafePasswordHandle
    {
        private IntPtr CreateHandle(string password)
        {
            return StringToHGlobalUTF32(password);
        }

        private IntPtr CreateHandle(SecureString password)
        {
            return Marshal.SecureStringToGlobalAllocAnsi(password);
        }

        private void FreeHandle()
        {
            Marshal.FreeHGlobal(handle);
            // Marshal.ZeroFreeGlobalAllocAnsi(handle);
        }

        //Copy from Masrshal package with modification to support UTF32
        private static unsafe IntPtr StringToHGlobalUTF32(string s)
        {
            int size_of_wchar_t = 4;
            if (s is null)
            {
                return IntPtr.Zero;
            }

            long lnb = (s.Length + 1) * (long)size_of_wchar_t;
            int nb = (int)lnb;

            // Overflow checking
            if (nb != lnb)
            {
                throw new ArgumentOutOfRangeException(nameof(s));
            }

            IntPtr hglobal = Marshal.AllocHGlobal((IntPtr)nb);

            StringToUTF32String(s, (byte*)hglobal, nb);
            return hglobal;
        }

        private static unsafe int StringToUTF32String(string s, byte* buffer, int bufferLength, bool bestFit = false, bool throwOnUnmappableChar = false)
        {
            int convertedBytes;
            fixed (char* pChar = s)
            {
                convertedBytes = Encoding.UTF32.GetBytes(pChar, s.Length, buffer, bufferLength);
            }

            buffer[convertedBytes] = 0;

            return convertedBytes;
        }
    }
}
