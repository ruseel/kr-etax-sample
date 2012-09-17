package com.barostudio;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class LoadPKCS12 {
	
	@SuppressWarnings("rawtypes")
	public static void main(String[] args) throws Exception {
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
	}

}
