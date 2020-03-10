// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Runtime.InteropServices;

namespace System.Net
{
    // sspi.h
    [StructLayout(LayoutKind.Sequential)]
    internal struct SecPkgContext_StreamSizes
    {
        public long cbHeader;
        public long cbTrailer;
        public long cbMaximumMessage;
        public long cBuffers;
        public long cbBlockSize;
    }
}
