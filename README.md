
전자세금계산서 Java용 OpenSource 라이브러리로 구현하기 v1.0
========================================

by <정문식> ruseel@gmail.com

이 글에서는 전자세금계산서 인증을 위해 통과해야 하는 taxcerti.org의 단위기능 검증을 통과할 수 있도록 Java로 샘플 코드를 구현한다. 

이 글은 NIPA나 국세청과는 아무 관련이 없는 필자 개인적인 경험 공유이다. Java용 OpenSource 라이브러리를 사용해서 구현하고자 할 때 알게 된 라이브러리 사용법을 공유하려고 한다. 개발지침을 보면서 그 지침에 맞게 라이브러리를 사용하려면 어떻게 해야할지 알아야 하는 부분이 많아서 개별기능 검증 통과에 시간이 많이 걸렸는데 저와 같은 분들에게 도움이 되었으면 한다.필자가 지침을 보고 개발할 때 혼란스러웠던 부분이 줄어들 것이라고 생각한다. 

이 글을 읽고나면 taxcerti.org의 단위기능 검증을 통과할 수 있게 되는 것을 목표로 한다. 사용하기 쉽게 추상화 한 것은 아니고 사용하는 여러 라이브러리의 사용법을 이해하기 쉽게 Low-Level의 샘플을 제공하고 있다. 

사용하는 라이브러리 
=============
* Apache Santuario(org.apache.santuario.xmlsec) 1.5.2
* Apache HTTPComponents 4.2.1
* Xalan 2.7.1
* Bouncy Castle 1.5.2


샘플 소스코드 위치
============
http://github.com/ruseel/kr-etax-sample


개요
===
필자가 보기에 "전자세금계산서 개발지침"의 기술적인 세부사항을 익히기 위해 통과해야 하는 최소한의 검증은 크게 세 가지다. 이 세가지는 taxcerti.org의 메뉴로 보면 A.전자세금계산서 검증, B.전자세금계산서 보안검증, C. (웹서비스 메세징 > 전자세금계산서 제출) 이다. 


이 세가지를 통과하고 나면 나머지는 얼마나 잘 추상화한 라이브러리 만들어 유연하고도 강력하게 쓸 수 있을 것인가로 보인다. 


구현 샘플 
======

PKCS#12를 사용해 PrivateKey, X509Certificate 로딩 
--------------------------------------------------
A,B,C 모두 java.security.PrivateKey, java.security.cert.X509Certificate 를 이용하는 경우가 많다. 은행이나 공인인증기관에서 발급받은 인증서를 PKCS#12로 "내보내기"하고 그 파일을 Java에서 JCA API의 KeyStore 인터페이스를 통해 로딩할 수 있다. 

JCA는 Java Cryptography Architect의 약자이고 JDK에 내장되어 있는 API 묶음이다. 여러 회사가 이 JCA를 통해서 암호화,전자서명과 관련된 기능을 이용할 수 있도록 해주는 라이브러리를 제공한다. 그런 라이브러리 중에 가장 여러곳에 쓰이는 것이 Bouncy Castle 이다. 그래서 BouncyCastle을 JCA의 Provider로서 이용한다고 표현한다. 

BouncyCastle을 Provier로 이용해 JCA의 KeyStore 인터페이스를 통해 다음과 같이 로딩할 수 있다.
LoadPKCS12파일에 전체 코드를 수록하였다.

실행시킬 때 첫번째 인자로 p12확장자 파일을 두 번째로 p12파일의 비밀번호를 입력한다.

```java
…
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
…
Security.addProvider(new BouncyCastleProvider());
         
KeyStore ks = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
char[] password = args[1].toCharArray();
ks.load(new FileInputStream(args[0]), password);

Enumeration e=ks.aliases();
if (!e.hasMoreElements()) {
        throw new RuntimeException("No aliases");
}
String alias = (String)e.nextElement();

PrivateKey privateKey = (PrivateKey) ks.getKey(alias, password);
X509Certificate cert = (X509Certificate) ks.getCertificate(alias);

System.out.println(privateKey);
System.out.println(cert);
```


KeyStore.load(inputstream, password)를 호출하고 나서 KeyStore.getKey(alias, password)로 PrivateKey를 KeyStore.getCertificates(alias)로 X509Certificate를 얻을 수 있다.



세금계산서XML에 전자서명하기 
-----------------------------

이렇게 얻은 PrivateKey와 X509Certificate를 가지고 XML에 Apache Saturiano(xmlsec)을 이용해 전자서명을 한다. xmlsec이 아니라 JDK에 내장된 JSR105(Java XML Digitial Signature API)를 쓸 수도 있을 듯 하다. 하지만 필자가 직접 사용해본 xmlsec만 샘플을 만들어 두었다. 


이 샘플은 2048bit 공인인증서를 내보내기한 p12파일을 이용해야만 가능하도록 코딩되어 있다. (다시말해 Digest알고리즘으로 SHA256을 사용한다.)

SignXML에 4개의 인자를 이런 순서로 주고 <p12 파일이름>, <p12파일의 비번>, <서명되기전의 전자세금계산서 XML path>, <서명된 전자세금계산서 path> 실행하고 나서 결과파일을 taxcerti.org의 단위기능별검증 >> 전자세금계산서 >> 2048비트 인증서로 서명된 전자세금계산서 업로드 >> 다음단계를 하고나면 모두 통과하는 것을 볼 수 있다. 

<서명되기전의 전자세금계산서 XML path>로 쓸 샘플 XML을 github의 src/main/resources/unsigned.xml에 넣었으니 이 파일을 사용해서 먼저 서명방법을 익히는 것이 좋겠다. 실수로 1024bit 인증서로 서명을 한다면 TC-TX-5003, TC-TX-7776이 실패한다. 조심할 것.

SignXML.java에 전체 소스를 수록해두었다. 


```java
// XMLSignature 객체를 만들고
String BaseURI = "";
XMLSignature sig = new XMLSignature(doc, BaseURI, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
// 그 객체안의 W3C Element를 DOM안에 삽입
{
  Element ctx = doc.createElementNS(null, "namespaceContext");            
  ctx.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:tax",
    "urn:kr:or:kec:standard:Tax:ReusableAggregateBusinessInformationEntitySchemaModule:1:0");
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
```


Rvalue를 PKCS#12에서 꺼내기 
-----------------------------
"전자세금계산서 개발지침"에서 "패키징/암호화"리고 지칭된 부분을 구현하려면 PrivateKey 포맷인 PKCS#8에서 특정 Attribute(PKCS#8의 용어)를 가져와야 한다. 

공개하기에는 완성도가 낮아 많이 부끄러운 코드이다. 단위기능 검증만을 통과하기 위해 rvalue를 얻어보고 싶었고, 딱 그렇게만 동작하지만 누군가에게 도움이 될 거라고 생각한다. 

Bouncy Castle의 JDKPKCS12KeyStore.java에서 일부분을 바꿔서 PKCS#8 안의 Rvalue attribute를 저장한다. 


SaveRvalue.java 파일에 전체 소스를 수록하였다. 

```java
// 다시 decrypt 해서 PrivateKeyInfo를 가져와본다
cipher.init(Cipher.DECRYPT_MODE, k, defParams);
PrivateKeyInfo       in = PrivateKeyInfo.getInstance(cipher.doFinal(data));
PrivateKey privKey = BouncyCastleProvider.getPrivateKey(in);

ASN1Set set = in.getAttributes();
Attribute attribute = Attribute.getInstance(set.getObjectAt(0));ASN1Encodable 	rValueAsASNEncodable = attribute.getAttributeValues()[0];
rvalue = ((DERBitString)rValueAsASNEncodable).getBytes();
```

unwrapXXXKey에 위와 같은 코드를 추가해서 rvalue를 얻고 keystore에서 getRvalue()로 얻을 수 있게 하였다. 



패키징,암호화 (ASN.1 TaxInvoicePackage구성, CMS 구현하기)
-----------------------------------------------------------
TaxInvoicePackage를 DER포맷으로 Encoding할 수 있어야 하는데 Bouncy Castle의 ASN.1 Object를 상속받아 구현했다. com.barostudio.nts.asn1.TaxInvoiceData, TaxInvoicePackage 파일에 전체 코드를 수록해 두었다. 


아래처럼 하면 DER로 인코딩된 byte array를 얻을 수 있다. 

```java
byte[] signerRvalue = readAll(rvaluefile);
byte[] taxInvoice = readAll(xmlfile);
TaxInvoiceData data = new TaxInvoiceData(signerRvalue, taxInvoice); 
TaxInvoicePackage pkg = new TaxInvoicePackage(new TaxInvoiceData[] { data });ByteArrayOutputStream baos = new ByteArrayOutputStream();
DEROutputStream out = new DEROutputStream(baos);out.writeObject(pkg); 
out.close();
      
return baos.toByteArray();
```

이렇게 얻은 byte array를 가지고 다음과 같이 Bouncy Castle의 CMSEnvelopedDataGenerator 클래스를 이용하면 전자세금계산서 단위기능 검증을 통과하는 파일을 만들 수 있다. 

```java
String rvaluefile = args[1];
String xmlfile = args[2];

byte[] _package = getTaxInvoicePackageAsBytes(rvaluefile, xmlfile);
CMSTypedData msg = new CMSProcessableByteArray(_package);

CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();
edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(
		kmCert("src/main/resources/kmCert.der")).setProvider("BC"));

CMSEnvelopedData ed = edGen.generate(msg,
		new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC)
				.setProvider("BC").build());
byte[] cmsEncryptedBytes = ed.getEncoded(); 

FileOutputStream out = new FileOutputStream("out.der");
out.write(cmsEncryptedBytes);
out.close();
```

rvalue를 저장한 파일과 패키징 하려는 서명된 xml파일을 command line 인자로 넘긴다. 생성된 out.der파일을 taxcerti.org의 (단위기능별검증 >> 전자세금계산서 >> 보안검증)에 업로드 하면 전부 통과하는 것을 확인 할 수 있다.


SOAP+SOAPwithAttachement+Apache Saturiano를+Apache HTTPComponents 사용해 전송하기
-------------------------------------------------------------------------------

SOAP Message 작성에는 java.xml.soal.* 클래스들을 사용하고 XML전자서명에는 Apache Saturiano(xmlsec)을 사용해서 HTTP로 전송할 XML을 작성한다. 

HTTP 전송에는 Apache HTTPCompoments 라이브러리를 사용한다. 

XML작성과 HTTP전송에 JAX-WS를 쓰는 방법도 시도해보았는데 wsimport를 써서 Class를 생성하고 Handler를 추가해서 WS-Security에 부합하는 요청을 taxcerti.org로 전송하는 것은 성공했지만 Attachment를 추가할 수 없어서 이렇게 HTTP Components를 쓰는 방법으로 바꿨다.


SubmitWithSOAP.java파일에 전체 소스가 있다.

```java
String p12file = args[0];
String p12password = args[1];
String cmsEncryptedFile = args[2];
String endPoint = args[3];		
```
전송사업자용 pkcs#12파일과 그 암호 (필자는 은행에서 발급받은 전자세금계산서용 공인인증서를 사용하였다), 그리고 CMS로 암호화 시킨  파일과 taxcerti.org에서 제공하는 URL을 넣으면 전송된다. 

```java
System.setProperty("org.apache.commons.logging.Log", "org.apache.commons.logging.impl.SimpleLog");
System.setProperty("org.apache.commons.logging.simplelog.showdatetime", "true");
System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.http", "debug");
System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.http.wire", "debug");
System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.xml.security.utils", "debug");
System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.xml.security.utils.DigesterOutputStream", "debug");
```
필자가 디버깅을 위해 사용하였던 Property 모음이다.


bulidMessage() 함수안에서 SOAP Header와 SOAP Body를 채운다. 필자가 더미값으로 채워넣은 값들이다. 이렇게 하여도 단위테스트 검증은 통과할 수 있다. 

```java
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

		// …
		// …
```


signMessage() 함수에서 SOAP메세지와 Attachement에 전자서명을 한다.

```java
private static void signMessage(SOAPMessage message, byte[] taxInvoiceBlob) throws Exception {
	SOAPPart part = message.getSOAPPart();
	SOAPEnvelope en = part.getEnvelope();
		
	String BaseURI = "";
	Document doc = (Document)en.getOwnerDocument();
	XMLSignature sig = new XMLSignature(doc, BaseURI, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
		
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
	
	// …
	// …
```

SignXML.java와 다르게 cid:taxInvoicePart를 전자서명에 추가하기 위한 코드가 들어가 있다.

이 코드가 돌아가기 위해 XMLSEC의 resolver와 transform을 하나씩 구현해야 했고 모두 com.barostudio.nts.ext 패키지 안에 들어 있다. 

프로그램의 시작부분에서 이렇게 Transform과 ResourceResolver 구현을 초기화하였다.

```java
org.apache.xml.security.transforms.Transform.register(wssswa, TransformAttachementContentSignature.class);
ResourceResolver.register(new ResolverOwnerDocumentUserData(), false);
```


맺으며
====

2012년 9월 17일 github에 올려놓은 코드를 이용해서 taxcerti.org의 단위검증을 통과하는 것을 확인하였다. 구현하면서 답답한 어느 순간에 이 글과 코드가 도움이 되었으면 하는 바램이다.

어떤 조언, 희망, 개선사항이라도 이메일로 보내주시면 감사하겠다.


FAQ
===
2048bit 공인인증서는 어떻게 구하나요? 

2012년 1월 이후로 발급받은 모든 공인인증서는 2048bit입니다. 전자세금계산서 발급을 위해 가지고 있는 공인인증서가 있으면 그것을 단위기능검증에 써도 됩니다.


안드로이드에서도 돌아갈까요? 

BoucnyCastle대신 StrongCastle을 쓰고 XMLSec을 약간 패치하면 Android에서도 전사서명을 할 수 있는 것을 확인했습니다. CMS는 잘 모르겠습니다.


JAX-WS로 구현하는 것이 가능하지 않을까요? 

SOAPwithAttachement를 위해 무언가 패치를 해야하지 가능하지 않을까 싶습니다. 적어도 JDK6에 포함되어 있는 JAX-WS RI는 그래 보였습니다. 정확하지는 않습니다. 

