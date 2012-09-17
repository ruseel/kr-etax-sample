package com.barostudio;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;

import org.bouncycastle.asn1.DEROutputStream;

import com.barostudio.nts.asn1.TaxInvoiceData;
import com.barostudio.nts.asn1.TaxInvoicePackage;

public class PackageTaxInvoice {

	public static void main(String[] args) throws Exception {
		String rvalueFile = args[0];
		String signedXMLFile = args[1];
		String derOutFile = args[2];
		
		TaxInvoicePackage pkg = new TaxInvoicePackage(new TaxInvoiceData[] {
			new TaxInvoiceData(readAll(rvalueFile), readAll(signedXMLFile))
		});
		
		DEROutputStream out = new DEROutputStream(new FileOutputStream(derOutFile));
		out.writeObject(pkg);
		out.close();
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
