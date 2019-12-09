using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;

namespace System.Security.Cryptography.Xml
{

    internal static class W3NAMESPACE
    {
        public const string NAME = "http://www.w3.org/2000/xmlns/";
    }

    internal static class SMEVStringComparer
    {
        private static readonly bool compareSetting;

        static SMEVStringComparer()
        {
            //var appSetting = ConfigurationManager.AppSettings["useAlphabeticalSort"];
            //if (!bool.TryParse(appSetting, out compareSetting))
            //{
            //    compareSetting = false;
            //}
            compareSetting = false;
        }

        public static int Compare(string s1, string s2)
        {
            return compareSetting ? s1.CompareTo(s2) : string.CompareOrdinal(s1, s2);
        }
    }

    internal static class UnescapedGtWriter
    {
        private static readonly Regex gtPattern = new Regex(@"(&gt;|&#62;)");
        private static readonly XmlWriterSettings settings = new XmlWriterSettings() { ConformanceLevel = ConformanceLevel.Fragment };

        public static void WriteString(XmlWriter writer, string value, bool escapeGt, bool isAttribute)
        {
            if (escapeGt)
            {
                writer.WriteString(value);
            }
            else
            {
                var sb = new StringBuilder();

                using (var tempWriter = XmlWriter.Create(sb, settings))
                {
                    tempWriter.WriteString(value);
                }

                if (isAttribute)
                {
                    writer.WriteRaw(gtPattern.Replace(sb.ToString(), ">").Replace("\"", "&quot;"));
                }
                else
                {
                    writer.WriteRaw(gtPattern.Replace(sb.ToString(), ">"));
                }
            }
        }
    }

    /// <summary>
    /// Правила трансформа описаны в http://forum.minsvyaz.ru/assets/files/app_5.docx
    /// </summary>
    public class XmlDsigSmevTransform : Transform
    {
        private XmlDocument innerDoc;
        private MemoryStream outputStream;
        private List<NamespaceInfo> namespaceMapping;
        private int nsCount;
        private int currentLevel;
        private Type[] inputTypes;
        private Type[] outputTypes;

        public XmlDsigSmevTransform()
        {
            this.inputTypes = new Type[] { typeof(Stream), typeof(XmlDocument) };
            this.outputTypes = new Type[] { typeof(Stream) };
            base.Algorithm = "urn://smev-gov-ru/xmldsig/transform";
            this.namespaceMapping = new List<NamespaceInfo>(); //namespaceUri, level, prefix
            this.UseOldEscaping = ReadEscapingSetting();
        }

        public bool UseOldEscaping { get; set; }

        public override object GetOutput(Type type)
        {
            if (type == typeof(XmlDocument))
            {
                var doc = new XmlDocument();
                doc.Load(this.OutputStream);
                return doc;
            }
            else if (type == typeof(Stream))
            {
                return this.OutputStream;
                ;
            }
            else
            {
                throw new ArgumentException(type.Name);
            }
        }

        public override object GetOutput()
        {
            return this.GetOutput(typeof(Stream));
        }

        public override Type[] InputTypes
        {
            get
            {
                return this.inputTypes;
            }
        }

        public override Type[] OutputTypes
        {
            get
            {
                return this.outputTypes;
            }
        }

        public override void LoadInnerXml(XmlNodeList nodeList)
        {
        }

        public override void LoadInput(object obj)
        {
            if (obj is XmlDocument)
            {
                this.innerDoc = (XmlDocument)obj;
            }
            else if (obj is Stream)
            {
                this.innerDoc = new XmlDocument();
                innerDoc.Load((Stream)obj);
            }
            else
            {
                throw new ArgumentException(obj.GetType().Name);
            }

            this.outputStream = null;
        }

        protected override XmlNodeList GetInnerXml()
        {
            return null;// (this.GetOutput(typeof(XmlDocument)) as XmlDocument).SelectNodes("//*");
        }

        private static bool ReadEscapingSetting()
        {
            //string appSetting = ConfigurationManager.AppSettings["useOldEscaping"];

            //bool setting = false;
            //return bool.TryParse(appSetting, out setting) ? setting : false;
            return false;
        }

        private MemoryStream OutputStream
        {
            set
            {
                this.outputStream = value;
            }

            get
            {
                if (this.outputStream == null)
                {
                    this.DoSmevTransform();
                }
                this.outputStream.Position = 0;
                return this.outputStream;
            }
        }

        /// <summary>
        /// Текущий уровень вложенности узла XML документа
        /// </summary>
        private int CurrentLevel
        {
            get
            {
                return this.currentLevel;
            }

            set
            {
                if (value < this.currentLevel)
                {
                    // при переходе на уровень выше удаляются все известные пространства имен на текущем уровне,
                    // т.к. они уже не нужны
                    this.namespaceMapping.RemoveAll(t => t.Depth > value);
                }

                this.currentLevel = value;
            }
        }

        /// <summary>
        /// Главный метод преобразования
        /// </summary>
        private void DoSmevTransform()
        {
            if (this.innerDoc == null)
            {
                throw new InvalidOperationException("Not initalized");
            }

            var settings = new XmlWriterSettings()
            {
                NewLineHandling = System.Xml.NewLineHandling.None, // по умолчанию - replace
                OmitXmlDeclaration = true, // правило 1 - удаление заголовка XML
                ConformanceLevel = System.Xml.ConformanceLevel.Fragment,
                Encoding = new UTF8Encoding(false)
            };

            this.outputStream = new MemoryStream();
            var writer = XmlWriter.Create(this.outputStream, settings);
            this.namespaceMapping.Clear();
            this.nsCount = 0;
            this.currentLevel = 0;

            using (var reader = new XmlNodeReader(this.innerDoc))
            {
                while (reader.Read())
                {
                    switch (reader.NodeType)
                    {
                        case XmlNodeType.XmlDeclaration:
                        case XmlNodeType.Comment:
                        case XmlNodeType.ProcessingInstruction:
                            // правило 1 - удаление комментариев и инструкций
                            break;

                        case XmlNodeType.Element:
                            this.CurrentLevel++;
                            var elementNS = reader.NamespaceURI;
                            if (!String.IsNullOrEmpty(elementNS))
                            {
                                string prefix;
                                // правило 6 - проверка префикса и генерация его в случае необходимости
                                var found = this.GetNamespacePrefix(elementNS, out prefix);
                                writer.WriteStartElement(prefix, reader.LocalName, elementNS);
                                if (!found)
                                {
                                    // правило 5 - объявление необъявленного пространства имен
                                    WriteNSAttribute(writer, elementNS, prefix);
                                }
                            }
                            else
                            {
                                writer.WriteStartElement(reader.LocalName);
                            }
                            if (reader.HasAttributes)
                            {
                                // обработка правил 4,7 и 8
                                this.ProcessAttributes(reader, writer, elementNS);
                            }

                            // правило 3 - преобразование в пару start-tag + end-tag
                            if (reader.IsEmptyElement)
                            {
                                writer.WriteFullEndElement();
                                this.CurrentLevel--;
                            }
                            break;

                        case XmlNodeType.Text:
                            // правило 2 - удаление значений из пробельных символов
                            if (!string.IsNullOrEmpty(reader.Value.Trim()))
                            {
                                UnescapedGtWriter.WriteString(writer, reader.Value, this.UseOldEscaping, false);
                            }
                            break;

                        case XmlNodeType.EndElement:
                            writer.WriteFullEndElement();
                            this.CurrentLevel--;
                            break;
                    }
                }

                writer.Flush();
            }
        }

        private static void WriteNSAttribute(XmlWriter writer, string namespaceURI, string prefix)
        {
            writer.WriteStartAttribute("xmlns", prefix, W3NAMESPACE.NAME);
            writer.WriteString(namespaceURI);
            writer.WriteEndAttribute();
        }

        private bool GetNamespacePrefix(string orginalUri, out string prefix)
        {
            var found = true;

            // проверка, было ли ужн объявлено пространство имен
            var ni = this.namespaceMapping.Find(t => t.NamespaceURI.Equals(orginalUri));

            if (ni == null)
            {
                found = false;
                // считаем пространство имен объявленным, заодно и создаем для него префикс по правилу 6
                ni = new NamespaceInfo(orginalUri, this.currentLevel, string.Format("ns{0}", ++nsCount));
                this.namespaceMapping.Add(ni);
            }

            prefix = ni.Prefix;
            return found;
        }

        private void ProcessAttributes(XmlReader reader, XmlWriter writer, string elementNS)
        {
            var attrs = new List<XmlAttributeInfo>();
            var namespaces = new List<string>();
            bool found;
            string prefix;

            reader.MoveToFirstAttribute();
            do
            {
                if (reader.NamespaceURI == W3NAMESPACE.NAME)
                {
                    if (reader.Value == elementNS)
                    {
                        // если это пространство имен элемента, то оно записывается отдельно первым - правило 7
                        continue;
                    }
                    else
                    {
                        // добавление для дальнейшей сортировки
                        namespaces.Add(reader.Value);
                    }
                }
                else
                {
                    // добавление для дальнейшей сортировки
                    attrs.Add(new XmlAttributeInfo(reader));
                }
            }
            while (reader.MoveToNextAttribute());

            attrs.Sort();
            namespaces.Sort();

            foreach (var ns in namespaces)
            {
                // объявление пространства имен только если оно используется - правило 4
                if (attrs.Exists(a => a.NamespaceURI.Equals(ns)))
                {
                    found = this.GetNamespacePrefix(ns, out prefix);
                    if (!found)
                    {
                        // объявление пространства имен только если оно не было уже объявлено - правило 5
                        WriteNSAttribute(writer, ns, prefix);
                    }
                }
            }

            foreach (var ai in attrs)
            {
                if (string.IsNullOrEmpty(ai.NamespaceURI))
                {
                    // запись unqualified атрибута
                    writer.WriteStartAttribute(null, ai.LocalName, null);
                }
                else
                {
                    // запись qualified атрибута с префиксом - он уже должен быть объявлен
                    this.GetNamespacePrefix(ai.NamespaceURI, out prefix);
                    writer.WriteStartAttribute(prefix, ai.LocalName, ai.NamespaceURI);
                }

                UnescapedGtWriter.WriteString(writer, ai.Value, this.UseOldEscaping, true);
                writer.WriteEndAttribute();
            }

            reader.MoveToElement();
        }

        private class NamespaceInfo
        {
            public NamespaceInfo(string namespaceURI, int depth, string prefix)
            {
                this.NamespaceURI = namespaceURI;
                this.Depth = depth;
                this.Prefix = prefix;
            }

            public string NamespaceURI { get; private set; }

            public int Depth { get; private set; }

            public string Prefix { get; private set; }
        }

        private class XmlAttributeInfo : IComparable
        {
            public XmlAttributeInfo(XmlReader reader)
                : this(reader.LocalName, reader.NamespaceURI, reader.Value)
            {
            }

            public XmlAttributeInfo(string localName, string namespaceURI, string value)
            {
                this.LocalName = localName;
                this.NamespaceURI = namespaceURI;
                this.Value = value;
            }

            public string Value { get; private set; }

            public string LocalName { get; private set; }

            public string NamespaceURI { get; private set; }

            #region IComparable Members

            // сортировка атрибутов по правилу 7
            public int CompareTo(object obj)
            {
                if (obj is XmlAttributeInfo)
                {
                    var ai = (XmlAttributeInfo)obj;

                    // unqualified в конец
                    if (string.IsNullOrEmpty(this.NamespaceURI) && !string.IsNullOrEmpty(ai.NamespaceURI))
                    {
                        return 1;
                    }

                    // unqualified в конец
                    if (!string.IsNullOrEmpty(this.NamespaceURI) && string.IsNullOrEmpty(ai.NamespaceURI))
                    {
                        return -1;
                    }

                    // сначала по пространству имен
                    int res = SMEVStringComparer.Compare(this.NamespaceURI, ai.NamespaceURI);
                    if (res == 0)
                    {
                        // потом по local name
                        res = SMEVStringComparer.Compare(this.LocalName, ai.LocalName);
                    }

                    return res;
                }
                else
                {
                    throw new ArgumentException();
                }
            }

            #endregion IComparable Members
        }
    }
}
