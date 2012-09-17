package com.barostudio.nts.asn1;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;

@SuppressWarnings("rawtypes")
public class TaxInvoiceData extends ASN1Object {
	/**
	 * TaxIvnoiceData ::= SEQUENCE {
  	 *  	rvalue SignerRvalue,
  	 * 		taxInvoice TaxInvoice }
	 */
	public ASN1OctetString signerRvalue;
	public ASN1OctetString taxInvoice;
	
	public static TaxInvoiceData getInstance(Object obj) {
		return new TaxInvoiceData(ASN1Sequence.getInstance(obj));
	}
	
	public TaxInvoiceData(ASN1Sequence seq) {
		Enumeration e = seq.getObjects();
		signerRvalue = ASN1OctetString.getInstance(e.nextElement());
		taxInvoice = ASN1OctetString.getInstance(e.nextElement());
	}
	
	public TaxInvoiceData(byte[] signerRvalue, byte[] taxInvoice) {
		this.signerRvalue = new DEROctetString(signerRvalue);
		this.taxInvoice = new DEROctetString(taxInvoice);
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector seq = new ASN1EncodableVector();
		seq.add(signerRvalue);
		seq.add(taxInvoice);
		
		return new DERSequence(seq);
	}

}
