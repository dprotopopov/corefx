using System.Runtime.InteropServices;

namespace System.Security.Cryptography
{
    /// <summary>
    /// Класc формирования подписи на алгоритме ГОСТ Р 34.10-2001.
    /// </summary>
    ///
    /// <remarks>
    /// Создает подпись, на алгоритме ГОСТ Р 34.10-2001. Для проверки подписи
    /// существует класс GostSignatureDeformatter.
    /// </remarks>
    ///
    /// <doc-sample path="Simple\DocBlock" name="SignatureFormatter"
    /// region="SignatureFormatter">Пример, вычисления подписи при помощи
    /// <c>GostSignatureFormatter</c>.</doc-sample>
    ///
    /// <basedon cref="System.Security.Cryptography.RSAPKCS1SignatureFormatter"/>
    /// <basedon cref="System.Security.Cryptography.DSASignatureFormatter"/>
    [ComVisible(true)]
    public class GostSignatureDeformatter : AsymmetricSignatureDeformatter
    {
        /// <summary>
        /// Ключ.
        /// </summary>
        private Gost3410 _gostKey;

        /// <summary>
        /// OID алгоритма хэширования.
        /// </summary>
        private string _alg_algOid;

        /// <summary>
        /// Создание объекта класса <see cref="GostSignatureDeformatter"/>.
        /// </summary>
        public GostSignatureDeformatter()
        {
            _alg_algOid = CryptoConfig.MapNameToOID(GostConstants.GOST3411_STRING);
        }

        /// <summary>
        /// Создание объекта класса <see cref="GostSignatureDeformatter"/>
        /// с заданным ключом.
        /// </summary>
        ///
        /// <param name="key">Провайдер, содержащий ключ.</param>
        ///
        /// <doc-sample path="Simple\DocBlock" name="SignatureFormatter"
        /// region="SignatureFormatter">Пример, вычисления подписи при
        /// помощи GostSignatureFormatter.</doc-sample>
        ///
        /// <argnull name="key" />
        /// <exception cref="CryptographicException">Параметр
        /// <paramref name="key"/> не является реализацией
        /// алгоритма ГОСТ Р 34.10-2001.</exception>
        public GostSignatureDeformatter(AsymmetricAlgorithm key)
            : this()
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            Gost3410 gost = key as Gost3410;
            if (gost == null)
                throw new ArgumentNullException(nameof(gost));
            _gostKey = gost;
        }

        /// <summary>
        /// Создает подпись на значение хэш-функции.
        /// </summary>
        ///
        /// <param name="rgbHash">Подписываемый хэш.</param>
        ///
        /// <returns>Подпись для <paramref name="rgbHash"/></returns>
        ///
        /// <remarks><para>
        /// Ключ и алгоритм хэширования должны быть определены до вызова
        /// этого метода.</para></remarks>
        ///
        /// <doc-sample path="Simple\DocBlock" name="SignatureFormatter"
        /// region="SignatureFormatter">Пример, вычисления подписи при помощи
        /// <c>GostSignatureFormatter</c>.</doc-sample>
        ///
        /// <exception cref="CryptographicUnexpectedOperationException">
        /// Не установлен алгоритм хэширования или ключ</exception>
        /// <argnull name="rgbHash" />
        public override bool VerifySignature(byte[] rgbHash, byte[] rgbSignature)
        {
            if (rgbHash == null)
                throw new ArgumentNullException(nameof(rgbHash));
            if (_alg_algOid == null)
                throw new CryptographicUnexpectedOperationException(SR.Cryptography_MissingOID);
            if (_gostKey == null)
                throw new CryptographicUnexpectedOperationException(SR.Cryptography_MissingKey);
            return _gostKey.VerifyHash(rgbHash, rgbSignature, HashAlgorithmName.Gost3411);
        }

        /// <summary>
        /// Устанавливает алгоритм хэширования, используемый при создании
        /// подписи.
        /// </summary>
        ///
        /// <param name="strName">Название алгоритма.</param>
        ///
        /// <exception cref="CryptographicUnexpectedOperationException">
        /// Устанавливаемое имя алгоритма неизвестно или не поддерживает
        /// алгоритм ГОСТ Р 34.11-2001.</exception>
        public override void SetHashAlgorithm(string strName)
        {
            if (CryptoConfig.MapNameToOID(strName) != this._alg_algOid)
                throw new CryptographicUnexpectedOperationException(
                    SR.Cryptography_InvalidOperation);
        }

        /// <summary>
        /// Устанавливает ключ, используемый при создании подписи.
        /// </summary>
        ///
        /// <param name="key">Объект, содержащий ключ.</param>
        ///
        /// <argnull name="key" />
        /// <exception cref="CryptographicException">Параметр
        /// <paramref name="key"/> не является реализацией
        /// алгоритма ГОСТ Р 34.10-2001.</exception>
        public override void SetKey(AsymmetricAlgorithm key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            _gostKey = (Gost3410)key;
        }
    }
}
