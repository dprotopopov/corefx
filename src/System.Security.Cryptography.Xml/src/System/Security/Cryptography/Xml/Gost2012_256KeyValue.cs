using System.Xml;

namespace System.Security.Cryptography.Xml
{
    /// <summary>
    /// Представляет закрытый ключ ГОСТ 34.10-2012 256 элемента &lt;KeyInfo&gt;.
    /// </summary>
    /// 
    /// <remarks><para>
    /// Класс <see cref="System.Security.Cryptography.Xml.KeyInfo"/> 
    /// представляет элемент &lt;KeyInfo&gt;, содержащий открытый ключ ГОСТ 34.10-2012 256. 
    /// </para>
    /// <para>Используйте <c>GostKeyValue</c> для идентификации открытого ключа, 
    /// соответствующего закрытому ключу ГОСТ 34.10-2012 256, который был использован 
    /// для создания цифровой подписи.</para>
    /// <para>Если ключ не предоставляется конструктору явно, новая пара ключей 
    /// ГОСТ 34.10-2012 256 генерируется случайным образом.</para>
    /// <para>Класс <c>GostKeyValue</c> используется с подписями XML. С 
    /// дополнительными сведениями о спецификации консорциума W3C можно ознакомиться 
    /// на веб-узле http://www.w3.org/TR/xmldsig-core/. Дополненения к спецификации 
    /// для российских стандартов
    /// описано в <a href="http://GOSTXMLMORE">Using GOST Algorithms for XML Security</a>.
    /// </para>
    /// </remarks>
    public class Gost2012_256KeyValue : KeyInfoClause
    {
        /// <summary>
        /// Инициализирует новый экземпляр класса <c>GostKeyValue</c> с новым, 
        /// сгенерированным случайным образом открытым ключом ГОСТ 34.10-2012 256.
        /// </summary>
        /// <remarks>При создании нового ключа ГОСТ 34.10-2012 256 этот конструктор 
        /// использует реализацию <see cref="Gost3410_2012_256"/> по 
        /// умолчанию, как определено классом 
        /// <see cref="System.Security.Cryptography.CryptoConfig"/>.</remarks>
        public Gost2012_256KeyValue()
        {
            _key = (Gost3410_2012_256)Gost3410_2012_256.Create();
        }

        /// <summary>
        /// Инициализирует новый экземпляр класса <c>GostKeyValue</c> с заданным 
        /// открытым ключом ГОСТ 34.10-2012 256.
        /// </summary>
        /// 
        /// <param name="key">Экземпляр реализации класса 
        /// <see cref="Gost2012_256KeyValue"/>, в котором содержится открытый 
        /// ключ.</param>
        public Gost2012_256KeyValue(Gost3410_2012_256 key)
        {
            _key = key;
        }

        /// <summary>
        /// Возвращает XML представление подэлемента GostKeyValue 
        /// </summary>
        /// 
        /// <returns>XML представление подэлемента GostKeyValue 
        /// <see cref="KeyInfo"/>.</returns>
        /// 
        /// <remarks><para>Данный метод служит для преобразования выходных 
        /// данных объекта <c>GostKeyValue</c> в формат XML.</para></remarks>
        public override XmlElement GetXml()
        {
            XmlDocument document1 = new XmlDocument();
            document1.PreserveWhitespace = true;
            return GetXml(document1);
        }

        /// <summary>
        /// Возвращает XML представление подэлемента GostKeyValue.
        /// </summary>
        /// 
        /// <param name="xmlDocument">XML документ.</param>
        /// 
        /// <returns>XML элемент представления.</returns>
        internal override XmlElement GetXml(XmlDocument xmlDocument)
        {
            // Несмотря на то что функция очень похожа на ParamsToXmlString
            // не удается их объединить.
            // С одной стороны, нет возможности втащить полноценный XML parser
            // в cpBase (зависимость только от system), с другой нам необходим
            // namespace в именах.
            Gost3410Parameters parameters = _key.ExportParameters(false);
            XmlElement keyValue = xmlDocument.CreateElement(
                "KeyValue", GostConstants.XmlDsigNamespace);
            XmlElement gostKeyValue = xmlDocument.CreateElement(
                GostConstants.TagKeyValue2001, GostConstants.XmlDsigNamespace);

            XmlElement publicKeyParameters = xmlDocument.CreateElement(
                GostConstants.TagPublicKeyParameters, GostConstants.XmlDsigNamespace);

            XmlElement publicKeyParamSet = xmlDocument.CreateElement(
                GostConstants.TagPublicKeyParamSet, GostConstants.XmlDsigNamespace);
            publicKeyParamSet.AppendChild(xmlDocument.CreateTextNode("urn:oid:" + parameters.PublicKeyParamSet));

            XmlElement digestParamSet = xmlDocument.CreateElement(
                GostConstants.TagDigestParamSet, GostConstants.XmlDsigNamespace);
            digestParamSet.AppendChild(xmlDocument.CreateTextNode("urn:oid:" + parameters.DigestParamSet));

            XmlElement encryptionParamSet = null;
            if (parameters.EncryptionParamSet != null)
            {
                xmlDocument.CreateElement(GostConstants.TagEncryptionParamSet,
                    GostConstants.XmlDsigNamespace);
                encryptionParamSet.AppendChild(xmlDocument.CreateTextNode("urn:oid:" + parameters.EncryptionParamSet));
            }

            XmlElement publicKey = xmlDocument.CreateElement(
                GostConstants.TagPublicKey, GostConstants.XmlDsigNamespace);
            publicKey.AppendChild(xmlDocument.CreateTextNode(Convert.ToBase64String(parameters.PublicKey)));

            publicKeyParameters.AppendChild(publicKeyParamSet);
            publicKeyParameters.AppendChild(digestParamSet);
            if (encryptionParamSet != null)
                publicKeyParameters.AppendChild(encryptionParamSet);

            gostKeyValue.AppendChild(publicKeyParameters);
            gostKeyValue.AppendChild(publicKey);
            keyValue.AppendChild(gostKeyValue);
            return keyValue;
        }

        /// <summary>
        /// Загружает состояние GostKeyValue из элемента XML.
        /// </summary>
        /// 
        /// <param name="value">Элемент XML, из которого загружается 
        /// состояние GostKeyValue.</param>
        /// 
        /// <argnull name="value" />
        public override void LoadXml(XmlElement value)
        {
            if (value == null)
                throw new ArgumentNullException("value");
            _key.FromXmlString(value.OuterXml);
        }

        /// <summary>
        /// Возвращает или устаналивает объект <see cref="Gost3410_2012_256"/>, 
        /// которому принадлежит открытый ключ.
        /// </summary>
        public Gost3410_2012_256 Key
        {
            get
            {
                return _key;
            }
            set
            {
                _key = value;
            }
        }

        /// <summary>
        /// Объект <see cref="Gost3410_2012_256"/>, которому принадлежит открытый ключ.
        /// </summary>
        private Gost3410_2012_256 _key;
    }
}
