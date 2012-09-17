package com.barostudio.nts.ext;

import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.utils.resolver.ResourceResolverException;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;
import org.w3c.dom.Attr;

public class ResolverOwnerDocumentUserData extends ResourceResolverSpi {
	@Override
	public XMLSignatureInput engineResolve(Attr uri, String baseURI)
			throws ResourceResolverException {
		byte[] x = (byte[]) uri.getOwnerDocument().getUserData(uri.getNodeValue());
		return new XMLSignatureInput(x);
	}

	@Override
	public boolean engineCanResolve(Attr uri, String baseURI) {
		if (uri == null) {
            return false;
        }

        String uriNodeValue = uri.getNodeValue();

        if (uriNodeValue.equals("") || (uriNodeValue.charAt(0)=='#') ||
            uriNodeValue.startsWith("http:")) {
            return false;
        }

        if (uriNodeValue.startsWith("cid:") || baseURI.startsWith("cid:")) {
            return true;
        }
        
        return false;
	}

}
