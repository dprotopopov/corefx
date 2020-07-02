// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Runtime.InteropServices;

namespace System.Net
{
    // sspi.h
    [StructLayout(LayoutKind.Sequential)]
    internal struct SecPkgContext_Sizes
    {
        public readonly long cbMaxToken;
        public readonly long cbMaxSignature;
        public readonly long cbBlockSize;
        public readonly long cbSecurityTrailer;
    }
}
