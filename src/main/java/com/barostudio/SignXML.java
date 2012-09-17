package com.barostudio;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.apache.xpath.XPathAPI;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

public class SignXML {
	
	private static PrivateKey privateKey;
	private static X509Certificate cert;

	public static void main(String[] args) throws Exception {
		String p12file = args[0];
		String p12password = args[1];
		String inputXML = args[2];
		String outputXML = args[3];
		
		loadPrivateKeyAndCertificates(p12file, p12password);
		sign(privateKey, cert, new FileInputStream(inputXML), new FileOutputStream(outputXML));
	}

	@SuppressWarnings("rawtypes")
	private static void loadPrivateKeyAndCertificates(String p12file, String p12password) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		 
		KeyStore ks = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
		char[] password = p12password.toCharArray();
		ks.load(new FileInputStream(p12file), password);
		
		Enumeration e=ks.aliases();
		if (!e.hasMoreElements()) {
			throw new RuntimeException("No aliases");
		}
		String alias = (String)e.nextElement();
		
		privateKey = (PrivateKey) ks.getKey(alias, password);
		cert = (X509Certificate) ks.getCertificate(alias);
	}

	
	public static void sign(PrivateKey privateKey, X509Certificate cert, InputStream is, OutputStream os)
			throws Exception {
		org.apache.xml.security.Init.init();
		
		// Document  만들기 
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		DocumentBuilder db = dbf.newDocumentBuilder();
		Document doc = db.parse(is);
		
		// XMLSignature 객체를 만들고  
		String BaseURI = "";
		XMLSignature sig = new XMLSignature(doc, BaseURI,
											XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
		// 그 객체안의 W3C Element를 DOM안에 삽입
		{
			Element ctx = doc.createElementNS(null, "namespaceContext");
			ctx.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:tax", "urn:kr:or:kec:standard:Tax:ReusableAggregateBusinessInformationEntitySchemaModule:1:0");
			Node pivot = XPathAPI.selectSingleNode(doc, "//tax:TaxInvoiceDocument", ctx);
			pivot.getParentNode().insertBefore(sig.getElement(), pivot);
		}
		
		//create the transforms object for the Document/Reference
		{
			Transforms transforms = new Transforms(doc);
			transforms.addTransform(Transforms.TRANSFORM_C14N_OMIT_COMMENTS);

			Element xpathElement = doc.createElementNS("http://www.w3.org/2000/09/xmldsig#", "ds:XPath");
			xpathElement.appendChild(doc.createTextNode("not(self::*[name() = 'TaxInvoice'] | ancestor-or-self::*[name() = 'ExchangedDocument'] | ancestor-or-self::ds:Signature)"));
			transforms.addTransform(Transforms.TRANSFORM_XPATH, xpathElement);

			sig.addDocument("", transforms, DigestMethod.SHA256);
		}
		
		// XMLSignature에 공개키 추가하고 서명
		sig.addKeyInfo(cert);
		sig.sign(privateKey);
		
		// OutputStream으로 document를 String으로 변환 출력 
		XMLUtils.outputDOMc14nWithComments(doc, os);
	}
}
