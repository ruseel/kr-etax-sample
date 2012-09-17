package com.barostudio.nts.asn1;

import java.math.BigInteger;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;

@SuppressWarnings("rawtypes")
public class TaxInvoicePackage extends ASN1Object {

	/**
	 * TaxInvoicePackage ::= SEQUENCE {
  	 *	count InvoiceCount,
  	 *	taxInvoiceSet TaxInvoiceSet }
     *
	 *	InvoiceCount ::= INTEGER
	 *	TaxInvoiceSet ::= SET SIZE (1..100) OF TaxInvoiceData
	 */
	
	public BigInteger count;
	public ASN1Set taxInvoiceSet;
	
	public TaxInvoicePackage(ASN1Sequence seq) {
		Enumeration e = seq.getObjects();
		
		count = ((ASN1Integer)e.nextElement()).getValue();
		taxInvoiceSet = (ASN1Set)e.nextElement();
	}
	
	public TaxInvoicePackage(TaxInvoiceData[] taxInvoices) {
		count = BigInteger.valueOf(taxInvoices.length);
		
		ASN1EncodableVector v = new ASN1EncodableVector();
		for (int i=0; i<taxInvoices.length; i++)
			v.add(taxInvoices[i]);
		
		taxInvoiceSet = ASN1Set.getInstance(new DERSet(v));
	}
	
	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();

		v.add(new DERInteger(count));
		v.add(taxInvoiceSet);
		
		return new DERSequence(v);
	}
}
