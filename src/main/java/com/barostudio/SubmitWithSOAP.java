package com.barostudio;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.nio.charset.Charset;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.namespace.QName;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPHeaderElement;
import javax.xml.soap.SOAPMessage;
import javax.xml.soap.SOAPPart;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Result;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.mime.FormBodyPart;
import org.apache.http.entity.mime.MultipartEntity;
import org.apache.http.entity.mime.content.FileBody;
import org.apache.http.entity.mime.content.StringBody;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Base64;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.apache.xml.security.utils.resolver.ResourceResolver;
import org.apache.xpath.XPathAPI;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import com.barostudio.nts.ext.ResolverOwnerDocumentUserData;
import com.barostudio.nts.ext.TransformAttachementContentSignature;

public class SubmitWithSOAP {
	public static final String wssswa = "http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Content-Signature-Transform";

	private static PrivateKey privateKey;
	private static X509Certificate cert;

	public static void main(String[] args) throws Exception {
		System.setProperty("org.apache.commons.logging.Log", "org.apache.commons.logging.impl.SimpleLog");
		System.setProperty("org.apache.commons.logging.simplelog.showdatetime", "true");
		System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.http", "debug");
		System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.http.wire", "debug");
		System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.xml.security.utils", "debug");
		System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.xml.security.utils.DigesterOutputStream", "debug");

		String p12file = args[0];
		String p12password = args[1];
		String cmsEncryptedFile = args[2];
		String endPoint = args[3];
		
		org.apache.xml.security.Init.init();
		org.apache.xml.security.transforms.Transform.register(wssswa, TransformAttachementContentSignature.class);
		ResourceResolver.register(new ResolverOwnerDocumentUserData(), false);
				
		loadPrivateKeyAndCertificates(p12file, p12password);
		byte[] taxInvoiceBlob = readAll(cmsEncryptedFile);

		SOAPMessage message = buildMessage(endPoint);
		signMessage(message, taxInvoiceBlob);
		
		Element document = message.getSOAPPart().getDocumentElement();
		submitWithSOAP(document, endPoint, cmsEncryptedFile);
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

	
	public static SOAPMessage buildMessage(String endPoint) throws SOAPException, Exception {
		MessageFactory factory = MessageFactory.newInstance();
		SOAPMessage message = factory.createMessage();

		SOAPHeader header = message.getSOAPHeader();
		SOAPPart part = message.getSOAPPart();
		SOAPEnvelope en = part.getEnvelope();
		SOAPBody body = message.getSOAPBody();
		SOAPHeader soapHeader = en.getHeader();
		if (soapHeader == null) {
			soapHeader = en.addHeader();
		}

		en.addNamespaceDeclaration("ds", "http://www.w3.org/2000/09/xmldsig#");
		en.addNamespaceDeclaration("kec", "http://www.kec.or.kr/standard/Tax/");
		en.addNamespaceDeclaration("wsa",
				"http://www.w3.org/2005/08/addressing");
		en.addNamespaceDeclaration(
				"wsse",
				"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
		en.addNamespaceDeclaration(
				"wsu",
				"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");
		en.addNamespaceDeclaration("xsd", "http://www.w3.org/2001/XMLSchema");
		en.addNamespaceDeclaration("xsi",
				"http://www.w3.org/2001/XMLSchema-instance");

		soapHeader.addChildElement("MessageID", "wsa").addTextNode(
				"20091013112725078-b9127eac9173494dab9ff31f57c84587");
		soapHeader.addChildElement("To", "wsa").addTextNode(endPoint);
		soapHeader.addChildElement("Action", "wsa").addTextNode(
				"http://www.kec.or.kr/standard/Tax/TaxInvoiceSubmit");

		SOAPElement kecMessageHeader = soapHeader.addChildElement(
				"MessageHeader", "kec");
		kecMessageHeader.addChildElement("Version", "kec").addTextNode("3.0");
		SOAPElement from = kecMessageHeader.addChildElement("From", "kec");
		from.addChildElement("PartyID", "kec").addTextNode("2208203228");
		from.addChildElement("PartyName", "kec").addTextNode(
				"National IT Industry Promotion Agency");
		SOAPElement to = kecMessageHeader.addChildElement("To", "kec");
		to.addChildElement("PartyID", "kec").addTextNode("9999999999");
		to.addChildElement("PartyName", "kec").addTextNode(
				"National Tax Service");

		kecMessageHeader.addChildElement("ReplyTo", "kec").addTextNode(
				"http://www.nipa.or.kr/etax/SendResultsService");
		kecMessageHeader.addChildElement("OperationType", "kec").addTextNode(
				"01");
		kecMessageHeader.addChildElement("MessageType", "kec")
				.addTextNode("01");
		kecMessageHeader.addChildElement("TimeStamp", "kec").addTextNode(
				"2009-10-13T14:27:25.109Z");

		SOAPHeaderElement security = soapHeader
				.addHeaderElement(new QName(
						"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
						"Security"));
		SOAPElement bst = security
				.addChildElement(new QName(
						"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
						"BinarySecurityToken"));
		bst.setAttribute(
				"EncodingType",
				"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
		bst.setAttribute(
				"ValueType",
				"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#X509v3");
		bst.setAttribute("wsu:Id", "X509Token");
		bst.addTextNode(Base64.encode(cert.getEncoded()));
		
		
		SOAPElement requestMessage = body.addChildElement("RequestMessage", "kec");
		requestMessage.addChildElement("SubmitID", "kec").addTextNode("12345678-20120904-0123456789abcdef0123456789abcdef");
		requestMessage.addChildElement("TotalCount", "kec").addTextNode("5");
		requestMessage.addChildElement("ReferenceID", "kec").addTextNode("taxInvoicePart");

		return message;
	}

	private static void signMessage(SOAPMessage message, byte[] taxInvoiceBlob) throws Exception {
		SOAPPart part = message.getSOAPPart();
		SOAPEnvelope en = part.getEnvelope();
		
		String BaseURI = "";
		Document doc = (Document)en.getOwnerDocument();
		XMLSignature sig = new XMLSignature(doc, BaseURI,
										XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
		
		{
			KeyInfo keyinfo = sig.getKeyInfo();
			Element keyinfoEl = keyinfo.getElement();
			Element securityTokenReference = doc.createElementNS(en.getNamespaceURI("wsse"), "wsse:SecurityTokenReference");
			Element ref = doc.createElementNS(en.getNamespaceURI("wsse"), "wsse:Reference");
			ref.setAttribute("URI", "#X509Token");
			securityTokenReference.appendChild(ref);
			keyinfoEl.appendChild(securityTokenReference);
		}

		{
			Transforms transforms = new Transforms(doc);
			transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
			transforms.addTransform(Transforms.TRANSFORM_C14N_OMIT_COMMENTS);
			sig.addDocument("", transforms, DigestMethod.SHA256);
		}
		
		doc.setUserData("cid:taxInvoicePart", taxInvoiceBlob, null);
		
		Transforms transforms = new Transforms(doc);
		transforms.addTransform(wssswa);
		sig.addDocument("cid:taxInvoicePart", transforms, DigestMethod.SHA256);
		
		// Security¾Æ·¡¿¡ ds:Signature »ðÀÔ 
		{
			Element ctx = doc.createElementNS(null, "namespaceContext");
			ctx.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:wsse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
			Node pivot = XPathAPI.selectSingleNode(doc, "//wsse:Security", ctx);
			pivot.appendChild(sig.getElement());
		}

		sig.sign(privateKey);
	}
	
	private static void submitWithSOAP(Element document, String endPoint, String cmsEncryptedFile)
			throws TransformerFactoryConfigurationError,
			Exception {
		String xmlAsString = asString(document);
		File taxInvoiceIS = new File(cmsEncryptedFile);

		HttpPost soapPost = new HttpPost(endPoint);
		MultipartEntity multipartEntity = new MultipartRelatedEntity();
		
		FormBodyPart xmlPart = new FormBodyPart("soap-req", new StringBody(xmlAsString, "text/xml", Charset.forName("UTF-8")));
		xmlPart.addField("Content-ID", "<SOAPPart>");
		multipartEntity.addPart(xmlPart);
		
		FormBodyPart taxInvoicePart = new FormBodyPart("taxinvoice", new FileBody(taxInvoiceIS));
		taxInvoicePart.addField("Content-ID", "<taxInvoicePart>");
		multipartEntity.addPart(taxInvoicePart);

		soapPost.setEntity(multipartEntity);
		soapPost.addHeader("Soapaction", "\"\"");
		soapPost.addHeader("Accept", "text/xml, multipart/related, text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2");
		
	
		DefaultHttpClient httpclient = new DefaultHttpClient();
		HttpResponse response = httpclient.execute(soapPost);
		System.out.println(response.getStatusLine());
		
		HttpEntity entity = response.getEntity();
		InputStream is = entity.getContent();
		BufferedReader r = new BufferedReader(new InputStreamReader(is, Charset.forName("UTF-8")));
		String line;
		while ((line = r.readLine()) != null) {
			System.out.println(line);
		}
		
		
		EntityUtils.consume(entity);

		try { httpclient.getConnectionManager().shutdown(); } catch (Exception ignore) {}
	}

	@SuppressWarnings("unused")
	private static String asString(Element el)
			throws TransformerFactoryConfigurationError,
			TransformerConfigurationException, TransformerException, Exception {
		String blob;
		if (false) {
			javax.xml.transform.TransformerFactory tfactory = TransformerFactory
					.newInstance();
			javax.xml.transform.Transformer xform = tfactory.newTransformer();
			javax.xml.transform.Source src = new DOMSource(el);
			xform.setOutputProperty(OutputKeys.INDENT, "yes");
			xform.setOutputProperty("{http://xml.apache.org/xslt}indent-amount",
					"4");
			java.io.StringWriter writer = new StringWriter();
			Result result = new javax.xml.transform.stream.StreamResult(writer);
			xform.transform(src, result);
			blob = writer.toString();
		} else {
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			XMLUtils.outputDOMc14nWithComments(el, baos);
			blob = baos.toString("UTF-8");
		}
		return blob;
	}
	
	public static byte[] readAll(String file) throws Exception {
		InputStream in = new FileInputStream(file);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		byte[] buffer = new byte[1024];
		int numRead;
		while ((numRead = in.read(buffer)) >= 0) {
			baos.write(buffer, 0, numRead); 
		}
		return baos.toByteArray();
	}

}
