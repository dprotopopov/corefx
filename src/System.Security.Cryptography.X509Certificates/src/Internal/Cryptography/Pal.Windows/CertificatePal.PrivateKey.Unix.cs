// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Text;
using System.Diagnostics;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;

using Internal.Cryptography.Pal.Native;

using SafeNCryptKeyHandle = Microsoft.Win32.SafeHandles.SafeNCryptKeyHandle;

namespace Internal.Cryptography.Pal
{
    internal sealed partial class CertificatePal : IDisposable, ICertificatePal
    {
        //
        // Returns the private key referenced by a store certificate. Note that despite the return type being declared "CspParameters",
        // the key can actually be a CNG key. To distinguish, examine the ProviderType property. If it is 0, this key is a CNG key with
        // the various properties of CspParameters being "repurposed" into storing CNG info. 
        // 
        // This is a behavior this method inherits directly from the Crypt32 CRYPT_KEY_PROV_INFO semantics.
        //
        // It would have been nice not to let this ugliness escape out of this helper method. But X509Certificate2.ToString() calls this 
        // method too so we cannot just change it without breaking its output.
        // 
        private CspParameters GetPrivateKeyCsp()
        {
            int cbData = 0;
            if (!Interop.crypt32.CertGetCertificateContextProperty(_certContext, CertContextPropId.CERT_KEY_PROV_INFO_PROP_ID, null, ref cbData))
            {
                int dwErrorCode = Interop.CPError.GetLastWin32Error();
                if (dwErrorCode == ErrorCode.CRYPT_E_NOT_FOUND)
                    return null;
                throw dwErrorCode.ToCryptographicException();
            }

            unsafe
            {
                byte[] privateKey = new byte[cbData];
                fixed (byte* pPrivateKey = privateKey)
                {
                    if (!Interop.crypt32.CertGetCertificateContextProperty(_certContext, CertContextPropId.CERT_KEY_PROV_INFO_PROP_ID, privateKey, ref cbData))
                        throw Interop.CPError.GetLastWin32Error().ToCryptographicException();
                    CRYPT_KEY_PROV_INFO* pKeyProvInfo = (CRYPT_KEY_PROV_INFO*)pPrivateKey;

                    CspParameters cspParameters = new CspParameters();
                    cspParameters.ProviderName = pwszToString((IntPtr)(pKeyProvInfo->pwszProvName));
                    cspParameters.KeyContainerName = pwszToString((IntPtr)(pKeyProvInfo->pwszContainerName));
                    cspParameters.ProviderType = pKeyProvInfo->dwProvType;
                    cspParameters.KeyNumber = pKeyProvInfo->dwKeySpec;
                    cspParameters.Flags = (CspProviderFlags)((pKeyProvInfo->dwFlags & CryptAcquireContextFlags.CRYPT_MACHINE_KEYSET) == CryptAcquireContextFlags.CRYPT_MACHINE_KEYSET ? CspProviderFlags.UseMachineKeyStore : 0);
                    return cspParameters;
                }
            }
        }
        private unsafe string pwszToString(IntPtr pwszName)
        {
            if (pwszName == IntPtr.Zero)
            {
                return null;
            }
            const int sizeof_wchar_t = 4;
            int len = 0;
            var curr = (byte*)pwszName;
            while(*curr != 0 || *(curr + 1) != 0 || *(curr + 2) != 0 || *(curr + 3) != 0)
            {
                len++;
                curr+=sizeof_wchar_t;
            }
            var buf = new byte[len*sizeof_wchar_t];
            Marshal.Copy(pwszName, buf, 0, len*sizeof_wchar_t);
            return Encoding.UTF32.GetString(buf);
        }
    }
}