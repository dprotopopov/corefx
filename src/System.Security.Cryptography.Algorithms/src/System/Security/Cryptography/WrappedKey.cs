//using System;
//using System.Collections.Generic;
//using System.Text;
//using System.Runtime.InteropServices;

//namespace System.Security.Cryptography
//{
//    /// <summary>
//    /// Алгоритм зашифрования секретного ключа.
//    /// </summary>
//    [ComVisible(true)]
//    public enum GostKeyWrapMethod
//    {
//        /// <summary>
//        /// GOST 28147-89 Key Wrap (см. 
//        /// <a href="http://www.ietf.org/rfc/rfc4357.txt">RFC 4357</a>).
//        /// </summary>
//        GostKeyWrap,
//        /// <summary>
//        /// CryptoPro Key Wrap (см. 
//        /// <a href="http://www.ietf.org/rfc/rfc4357.txt">RFC 4357</a>).
//        /// </summary>
//        CryptoProKeyWrap,

//        /// <summary>
//        /// CryptoPro Key Wrap 2012 (см. 
//        /// <a href="http://www.ietf.org/rfc/rfc4357.txt">RFC 4357</a>).
//        /// </summary>
//        CryptoPro12KeyWrap
//    };

//    // TODO: Номер draft RFC, в котором данная структура описана.

//    /// <summary>
//    /// Структура зашифрованного на алгоритме ГОСТ 28147 ключа.
//    /// </summary>
//    /// 
//    /// <remarks>
//    /// Данный класс служит для передачи ключевой информации, например, 
//    /// сессионных ключей.
//    /// </remarks>
//    internal class GostWrappedKeyObject
//    {
//        /// <summary>
//        /// Упаковка в ASN.1 структуру Gost3410-KeyWrap.
//        /// </summary>
//        /// <returns>Байтовый массив ASN.1 структуры Gost3410-KeyWrap.</returns>
//        public byte[] GetXmlWrappedKey()
//        {
//            return cpAsnUtils.EncodeXmlGostR3410WrappedKey(this);
//        }

//        /// <summary>
//        /// Получение структуры зашифрованного ключа на основе 
//        /// ASN.1 структуру Gost3410-KeyWrap.
//        /// </summary>
//        /// <param name="data">ASN.1 структура Gost3410-KeyWrap</param>
//        public void SetByXmlWrappedKey(byte[] data)
//        {
//            cpAsnUtils.DecodeXmlGostR3410WrappedKey(data, this);
//        }

//        public GostWrappedKey WrappedKey
//        {
//            get
//            {
//                GostWrappedKey ret;
//                ret.EncryptionParamSet = encryptionParamSet_;
//                ret.Ukm = ukm_;
//                ret.EncryptedKey = encryptedKey_;
//                ret.Mac = mac_;
//                return ret;
//            }
//            set
//            {
//                this.encryptionParamSet_ = value.EncryptionParamSet;
//                this.ukm_ = value.Ukm;
//                this.encryptedKey_ = value.EncryptedKey;
//                this.mac_ = value.Mac;
//            }
//        }

//        /// <summary>
//        /// OID параметров шифрования.
//        /// </summary>
//        internal string encryptionParamSet_;
//        /// <summary>
//        /// UKM.
//        /// </summary>
//        internal byte[] ukm_;
//        /// <summary>
//        /// Зашифрованный ключ.
//        /// </summary>
//        internal byte[] encryptedKey_;
//        /// <summary>
//        /// Message Authentication Code.
//        /// </summary>
//        internal byte[] mac_;
//    }

//    /// <summary>
//    /// Структура зашифрованного на алгоритме ГОСТ 28147 ключа.
//    /// </summary>
//    /// 
//    /// <remarks>
//    /// Данный класс служит для передачи ключевой информации, например, 
//    /// сессионных ключей.
//    /// </remarks>
//    /// 
//    [Serializable, ComVisible(true), StructLayout(LayoutKind.Sequential)]
//    public struct GostWrappedKey
//    {
//        /// <summary>
//        /// Контрольная сумма (Message Authentication Code) зашифрованного 
//        /// ключа.
//        /// </summary>
//        public byte[] Mac;

//        /// <summary>
//        /// UserKeyingMaterial
//        /// </summary>
//        public byte[] Ukm;

//        /// <summary>
//        /// OID параметров шифрования.
//        /// </summary>
//        public string EncryptionParamSet;

//        /// <summary>
//        /// Зашифрованный ключ.
//        /// </summary>
//        public byte[] EncryptedKey;

//        /// <summary>
//        /// Упаковка в ASN.1 структуру Gost3410-KeyWrap.
//        /// </summary>
//        /// <returns>Байтовый массив ASN.1 структуры Gost3410-KeyWrap.</returns>
//        public byte[] GetXmlWrappedKey()
//        {
//            GostWrappedKeyObject obj = new GostWrappedKeyObject();
//            obj.WrappedKey = this;
//            return cpAsnUtils.EncodeXmlGostR3410WrappedKey(obj);
//        }

//        /// <summary>
//        /// Упаковка в SIMPLE_BLOB.
//        /// </summary>
//        /// <returns>Байтовый массив SIMPLE_BLOB.</returns>
//        /// <exception cref="System.Security.Cryptography.CryptographicException">При ошибках
//        /// кодирования структуры.</exception>
//        /// 
//        /// <cspversions />
//#if SHARPEI_DESTINATION_FW40
//        [SecuritySafeCritical]
//#endif
//        public byte[] GetCryptoServiceProviderBlob()
//        {
//            GostWrappedKeyObject obj = new GostWrappedKeyObject();
//            obj.WrappedKey = this;
//            return COMCryptography.EncodeSimpleBlob(obj,
//                Constants.CALG_G28147);
//        }

//        /// <summary>
//        /// Получение структуры зашифрованного ключа на основе 
//        /// ASN.1 структуру Gost3410-KeyWrap.
//        /// </summary>
//        /// <param name="data">ASN.1 структура Gost3410-KeyWrap</param>
//        public void SetByXmlWrappedKey(byte[] data)
//        {
//            GostWrappedKeyObject obj = new GostWrappedKeyObject();
//            cpAsnUtils.DecodeXmlGostR3410WrappedKey(data, obj);
//            this = obj.WrappedKey;
//        }

//        /// <summary>
//        /// Распаковка объекта из SIMPLE_BLOB.
//        /// </summary>
//        /// <param name="data">Данные, закодированный SIMPLE_BLOB.</param>
//        /// <exception cref="System.Security.Cryptography.CryptographicException">При ошибках
//        /// декодирования структуры.</exception>
//        /// <argnull name="data" />
//        /// 
//        /// <cspversions />
//#if SHARPEI_DESTINATION_FW40
//        [SecurityCritical]
//#endif
//        public void SetByCryptoServiceProviderBlob(byte[] data)
//        {
//            if (data == null)
//                throw new ArgumentNullException("data");
//            GostWrappedKeyObject obj = new GostWrappedKeyObject();
//            COMCryptography.DecodeSimpleBlob(obj, data);
//            this = obj.WrappedKey;
//        }
//    }
//}
