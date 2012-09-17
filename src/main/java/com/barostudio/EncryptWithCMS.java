package com.barostudio;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.barostudio.nts.asn1.TaxInvoiceData;
import com.barostudio.nts.asn1.TaxInvoicePackage;

public class EncryptWithCMS {
	
	public static void main(String[] args) throws Exception {
		String rvaluefile = args[0];
		String xmlfile = args[1];
		String encryptedFile = args[2];
		
		byte[] _package = getTaxInvoicePackageAsBytes(rvaluefile, xmlfile);
		CMSTypedData msg = new CMSProcessableByteArray(_package);
		
		CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();
		edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(
				kmCert("src/main/resources/KmCert.der")).setProvider("BC"));
		
		CMSEnvelopedData ed = edGen.generate(msg,
				new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC)
						.setProvider("BC").build());
		byte[] cmsEncryptedBytes = ed.getEncoded(); 
		
		FileOutputStream out = new FileOutputStream(encryptedFile);
		out.write(cmsEncryptedBytes);
		out.close();
	}

	public static byte[] getTaxInvoicePackageAsBytes(String rvaluefile, String xmlfile) throws Exception {
		byte[] signerRvalue = readAll(rvaluefile);
		byte[] taxInvoice = readAll(xmlfile);
		TaxInvoiceData data = new TaxInvoiceData(signerRvalue, taxInvoice);
		
		TaxInvoicePackage pkg = new TaxInvoicePackage(new TaxInvoiceData[] { data });
		
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DEROutputStream out = new DEROutputStream(baos);
		out.writeObject(pkg);
		out.close();
		
		return baos.toByteArray();
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
	
	private static X509Certificate kmCert(String nipaTestCert) throws FileNotFoundException, CertificateException {
		Security.addProvider(new BouncyCastleProvider());
		 
		FileInputStream ksfis = new FileInputStream(nipaTestCert);
		BufferedInputStream ksbufin = new BufferedInputStream(ksfis);
		X509Certificate certificate = (X509Certificate)
		  CertificateFactory.getInstance("X.509").generateCertificate(ksbufin);
		return certificate;
	}
}
