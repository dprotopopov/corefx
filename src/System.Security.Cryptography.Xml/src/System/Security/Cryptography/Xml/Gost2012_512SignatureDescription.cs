// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

namespace System.Security.Cryptography.Xml
{
    internal class Gost2012_512SignatureDescription : SignatureDescription
    {
        public Gost2012_512SignatureDescription()
        {
            KeyAlgorithm = typeof(Gost3410_2012_512).AssemblyQualifiedName;
            FormatterAlgorithm = typeof(Gost2012_512SignatureFormatter).AssemblyQualifiedName;
            DeformatterAlgorithm = typeof(Gost2012_512SignatureDeformatter).AssemblyQualifiedName;
            DigestAlgorithm = GostConstants.GOST3411_2012_512STRING;
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
            return Gost3411_2012_512.Create();
        }
    }
}
