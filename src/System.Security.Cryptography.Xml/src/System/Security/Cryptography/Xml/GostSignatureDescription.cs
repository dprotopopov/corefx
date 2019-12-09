// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

namespace System.Security.Cryptography.Xml
{
    internal class GostSignatureDescription : SignatureDescription
    {
        public GostSignatureDescription()
        {
            KeyAlgorithm = typeof(Gost3410).AssemblyQualifiedName;
            FormatterAlgorithm = typeof(GostSignatureFormatter).AssemblyQualifiedName;
            DeformatterAlgorithm = typeof(GostSignatureDeformatter).AssemblyQualifiedName;
            DigestAlgorithm = GostConstants.GOST3411_STRING;
        }

        public sealed override AsymmetricSignatureDeformatter CreateDeformatter(AsymmetricAlgorithm key)
        {
            var item = (AsymmetricSignatureDeformatter)CryptoConfig.CreateFromName(DeformatterAlgorithm);
            item.SetKey(key);
            item.SetHashAlgorithm(DigestAlgorithm);
            return item;
        }

        public sealed override AsymmetricSignatureFormatter CreateFormatter(AsymmetricAlgorithm key)
        {
            var item = (AsymmetricSignatureFormatter)CryptoConfig.CreateFromName(FormatterAlgorithm);
            item.SetKey(key);
            item.SetHashAlgorithm(DigestAlgorithm);
            return item;
        }

        public sealed override HashAlgorithm CreateDigest()
        {
            return Gost3411.Create();
        }
    }
}
