package com.barostudio.nts.ext;

import java.io.IOException;
import java.io.OutputStream;

import javax.xml.parsers.ParserConfigurationException;

import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.transforms.Transform;
import org.apache.xml.security.transforms.TransformSpi;
import org.apache.xml.security.transforms.TransformationException;
import org.xml.sax.SAXException;

public class TransformAttachementContentSignature extends TransformSpi {

	public static String implementedTransformURI = 
			"http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Content-Signature-Transform";
	
	@Override
	protected String engineGetURI() {
		return implementedTransformURI;
	}

	@Override
	protected XMLSignatureInput enginePerformTransform(XMLSignatureInput input,
			OutputStream os, Transform transformObject) throws IOException,
			CanonicalizationException, InvalidCanonicalizerException,
			TransformationException, ParserConfigurationException, SAXException {
        return new XMLSignatureInput(input.getBytes());
	}
	
}
