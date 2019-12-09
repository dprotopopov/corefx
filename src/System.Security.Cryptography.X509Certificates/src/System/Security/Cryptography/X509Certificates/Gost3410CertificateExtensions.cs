// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Internal.Cryptography;
using Internal.Cryptography.Pal;

namespace System.Security.Cryptography.X509Certificates
{
    /// <summary>
    /// Provides extension methods for retrieving <see cref="Gost3410" /> implementations for the
    /// public and private keys of a <see cref="X509Certificate2" />.
    /// </summary>
    public static class Gost3410CertificateExtensions
    {
        /// <summary>
        /// Gets the <see cref="Gost3410" /> public key from the certificate or null if the certificate does not have an Gost3410 public key.
        /// </summary>
        public static Gost3410 GetGost3410PublicKey(this X509Certificate2 certificate)
        {
            return certificate.GetPublicKey<Gost3410>();
        }

        /// <summary>
        /// Gets the <see cref="Gost3410_2012_256" /> public key from the certificate or null if the certificate does not have an Gost3410 public key.
        /// </summary>
        public static Gost3410_2012_256 GetGost3410_2012_256PublicKey(this X509Certificate2 certificate)
        {
            return certificate.GetPublicKey<Gost3410_2012_256>();
        }

        /// <summary>
        /// Gets the <see cref="Gost3410_2012_512" /> public key from the certificate or null if the certificate does not have an Gost3410 public key.
        /// </summary>
        public static Gost3410_2012_512 GetGost3410_2012_512PublicKey(this X509Certificate2 certificate)
        {
            return certificate.GetPublicKey<Gost3410_2012_512>();
        }

        /// <summary>
        /// Gets the <see cref="Gost3410" /> private key from the certificate or null if the certificate does not have an Gost3410 private key.
        /// </summary>
        public static Gost3410 GetGost3410PrivateKey(this X509Certificate2 certificate)
        {
            return certificate.GetPrivateKey<Gost3410>();
        }

        /// <summary>
        /// Gets the <see cref="Gost3410_2012_256" /> private key from the certificate or null if the certificate does not have an Gost3410_2012_256 private key.
        /// </summary>
        public static Gost3410_2012_256 GetGost3410_2012_256PrivateKey(this X509Certificate2 certificate)
        {
            return certificate.GetPrivateKey<Gost3410_2012_256>();
        }

        /// <summary>
        /// Gets the <see cref="Gost3410_2012_512" /> private key from the certificate or null if the certificate does not have an Gost3410_2012_512 private key.
        /// </summary>
        public static Gost3410_2012_512 GetGost3410_2012_512PrivateKey(this X509Certificate2 certificate)
        {
            return certificate.GetPrivateKey<Gost3410_2012_512>();
        }

        public static X509Certificate2 CopyWithPrivateKey(this X509Certificate2 certificate, Gost3410 privateKey)
        {
            if (certificate == null)
                throw new ArgumentNullException(nameof(certificate));
            if (privateKey == null)
                throw new ArgumentNullException(nameof(privateKey));

            if (certificate.HasPrivateKey)
                throw new InvalidOperationException(SR.Cryptography_Cert_AlreadyHasPrivateKey);

            using (Gost3410 publicKey = GetGost3410PublicKey(certificate))
            {
                if (publicKey == null)
                    throw new ArgumentException(SR.Cryptography_PrivateKey_WrongAlgorithm);

                //Gost3410Parameters currentParameters = publicKey.ExportParameters(false);
                //Gost3410Parameters newParameters = privateKey.ExportParameters(false);
            }

            ICertificatePal pal = certificate.Pal.CopyWithPrivateKey(privateKey);
            return new X509Certificate2(pal);
        }

        public static X509Certificate2 CopyWithPrivateKey(this X509Certificate2 certificate, Gost3410_2012_256 privateKey)
        {
            if (certificate == null)
                throw new ArgumentNullException(nameof(certificate));
            if (privateKey == null)
                throw new ArgumentNullException(nameof(privateKey));

            if (certificate.HasPrivateKey)
                throw new InvalidOperationException(SR.Cryptography_Cert_AlreadyHasPrivateKey);

            using (Gost3410_2012_256 publicKey = GetGost3410_2012_256PublicKey(certificate))
            {
                if (publicKey == null)
                    throw new ArgumentException(SR.Cryptography_PrivateKey_WrongAlgorithm);

                //Gost3410Parameters currentParameters = publicKey.ExportParameters(false);
                //Gost3410Parameters newParameters = privateKey.ExportParameters(false);
            }

            ICertificatePal pal = certificate.Pal.CopyWithPrivateKey(privateKey);
            return new X509Certificate2(pal);
        }

        public static X509Certificate2 CopyWithPrivateKey(this X509Certificate2 certificate, Gost3410_2012_512 privateKey)
        {
            if (certificate == null)
                throw new ArgumentNullException(nameof(certificate));
            if (privateKey == null)
                throw new ArgumentNullException(nameof(privateKey));

            if (certificate.HasPrivateKey)
                throw new InvalidOperationException(SR.Cryptography_Cert_AlreadyHasPrivateKey);

            using (Gost3410_2012_512 publicKey = GetGost3410_2012_512PublicKey(certificate))
            {
                if (publicKey == null)
                    throw new ArgumentException(SR.Cryptography_PrivateKey_WrongAlgorithm);

                //Gost3410Parameters currentParameters = publicKey.ExportParameters(false);
                //Gost3410Parameters newParameters = privateKey.ExportParameters(false);
            }

            ICertificatePal pal = certificate.Pal.CopyWithPrivateKey(privateKey);
            return new X509Certificate2(pal);
        }
    }
}
