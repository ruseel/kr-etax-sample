package com.barostudio;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.Provider;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.AuthenticatedSafe;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.EncryptedData;
import org.bouncycastle.asn1.pkcs.MacData;
import org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
import org.bouncycastle.asn1.pkcs.Pfx;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.SafeBag;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.jcajce.provider.symmetric.util.BCPBEKey;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.JDKPKCS12KeyStore;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;


public class SaveRvalue {

	public static void main(String[] args) throws Exception {
		String p12file = args[0];
		String p12password = args[1];
		String rvalueOutFile = args[2];
		
		CustomPKCS12KeyStore ks = new CustomPKCS12KeyStore();
		ks.engineLoad(new FileInputStream(p12file), p12password.toCharArray());
		
		OutputStream out = new FileOutputStream(rvalueOutFile);
		out.write(ks.getRvalue());
	}

	
	static class CustomPKCS12KeyStore extends JDKPKCS12KeyStore {
		@SuppressWarnings("rawtypes")
		private Hashtable localIds;
		private IgnoresCaseHashtable keys;
		private byte[] rvalue;

		public CustomPKCS12KeyStore() {
			super(null, null, null);
		}
		
		public byte[] getRvalue() {
			return rvalue;
		}

		@SuppressWarnings({ "rawtypes", "deprecation", "unchecked", "unused" })
		public void engineLoad(InputStream stream, char[] password)
				throws IOException {
			if (stream == null) // just initialising
			{
				return;
			}

			if (password == null) {
				throw new NullPointerException(
						"No password supplied for PKCS#12 KeyStore.");
			}

			BufferedInputStream bufIn = new BufferedInputStream(stream);

			bufIn.mark(10);

			int head = bufIn.read();

			if (head != 0x30) {
				throw new IOException(
						"stream does not represent a PKCS12 key store");
			}

			bufIn.reset();

			ASN1InputStream bIn = new ASN1InputStream(bufIn);
			ASN1Sequence obj = (ASN1Sequence) bIn.readObject();
			Pfx bag = Pfx.getInstance(obj);
			ContentInfo info = bag.getAuthSafe();
			Vector chain = new Vector();
			boolean unmarkedKey = false;
			boolean wrongPKCS12Zero = false;

			if (bag.getMacData() != null) // check the mac code
			{
				MacData mData = bag.getMacData();
				DigestInfo dInfo = mData.getMac();
				AlgorithmIdentifier algId = dInfo.getAlgorithmId();
				byte[] salt = mData.getSalt();
				int itCount = mData.getIterationCount().intValue();

				byte[] data = ((ASN1OctetString) info.getContent()).getOctets();

				try {
					byte[] res = calculatePbeMac(algId.getObjectId(), salt,
							itCount, password, false, data);
					byte[] dig = dInfo.getDigest();

					if (!Arrays.constantTimeAreEqual(res, dig)) {
						if (password.length > 0) {
							throw new IOException(
									"PKCS12 key store mac invalid - wrong password or corrupted file.");
						}

						// Try with incorrect zero length password
						res = calculatePbeMac(algId.getObjectId(), salt,
								itCount, password, true, data);

						if (!Arrays.constantTimeAreEqual(res, dig)) {
							throw new IOException(
									"PKCS12 key store mac invalid - wrong password or corrupted file.");
						}

						wrongPKCS12Zero = true;
					}
				} catch (IOException e) {
					throw e;
				} catch (Exception e) {
					throw new IOException("error constructing MAC: "
							+ e.toString());
				}
			}

			keys = new IgnoresCaseHashtable();
			localIds = new Hashtable();

			if (info.getContentType().equals(data)) {
				bIn = new ASN1InputStream(
						((ASN1OctetString) info.getContent()).getOctets());

				AuthenticatedSafe authSafe = AuthenticatedSafe.getInstance(bIn
						.readObject());
				ContentInfo[] c = authSafe.getContentInfo();

				for (int i = 0; i != c.length; i++) {
					if (c[i].getContentType().equals(data)) {
						ASN1InputStream dIn = new ASN1InputStream(
								((ASN1OctetString) c[i].getContent())
										.getOctets());
						ASN1Sequence seq = (ASN1Sequence) dIn.readObject();

						for (int j = 0; j != seq.size(); j++) {
							SafeBag b = SafeBag.getInstance(seq.getObjectAt(j));
							if (b.getBagId().equals(pkcs8ShroudedKeyBag)) {
								org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo eIn = org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo
										.getInstance(b.getBagValue());
								
								PrivateKey privKey = unwrapXXKey(
										eIn.getEncryptionAlgorithm(),
										eIn.getEncryptedData(), password,
										wrongPKCS12Zero);

								System.out.println("privKey: " + privKey);
								//
								// set the attributes on the key
								//
								PKCS12BagAttributeCarrier bagAttr = (PKCS12BagAttributeCarrier) privKey;
								String alias = null;
								ASN1OctetString localId = null;

								if (b.getBagAttributes() != null) {
									Enumeration e = b.getBagAttributes()
											.getObjects();
									while (e.hasMoreElements()) {
										ASN1Sequence sq = (ASN1Sequence) e
												.nextElement();
										ASN1ObjectIdentifier aOid = (ASN1ObjectIdentifier) sq
												.getObjectAt(0);
										ASN1Set attrSet = (ASN1Set) sq
												.getObjectAt(1);
										ASN1Primitive attr = null;

										if (attrSet.size() > 0) {
											attr = (ASN1Primitive) attrSet
													.getObjectAt(0);

											ASN1Encodable existing = bagAttr
													.getBagAttribute(aOid);
											if (existing != null) {
												// OK, but the value has to be
												// the same
												if (!existing.toASN1Primitive()
														.equals(attr)) {
													throw new IOException(
															"attempt to add existing attribute with different value");
												}
											} else {
												bagAttr.setBagAttribute(aOid,
														attr);
											}
										}

										if (aOid.equals(pkcs_9_at_friendlyName)) {
											alias = ((DERBMPString) attr)
													.getString();
											keys.put(alias, privKey);
										} else if (aOid
												.equals(pkcs_9_at_localKeyId)) {
											localId = (ASN1OctetString) attr;
										}
									}
								}

								if (localId != null) {
									String name = new String(Hex.encode(localId
											.getOctets()));

									if (alias == null) {
										keys.put(name, privKey);
									} else {
										localIds.put(alias, name);
									}
								} else {
									unmarkedKey = true;
									keys.put("unmarked", privKey);
								}
							} else if (b.getBagId().equals(certBag)) {
								chain.addElement(b);
							} else {
								System.out.println("extra in data "
										+ b.getBagId());
								System.out.println(ASN1Dump.dumpAsString(b));
							}
						}
					} else if (c[i].getContentType().equals(encryptedData)) {
						System.out.println("encryptedData");
						EncryptedData d = EncryptedData.getInstance(c[i]
								.getContent());
						byte[] octets = cryptData(false,
								d.getEncryptionAlgorithm(), password,
								wrongPKCS12Zero, d.getContent().getOctets());
						ASN1Sequence seq = (ASN1Sequence) ASN1Primitive
								.fromByteArray(octets);

						for (int j = 0; j != seq.size(); j++) {
							SafeBag b = SafeBag.getInstance(seq.getObjectAt(j));

							if (b.getBagId().equals(certBag)) {
								chain.addElement(b);
							} else if (b.getBagId().equals(pkcs8ShroudedKeyBag)) {
								org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo eIn = org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo
										.getInstance(b.getBagValue());
								PrivateKey privKey = unwrapKey(
										eIn.getEncryptionAlgorithm(),
										eIn.getEncryptedData(), password,
										wrongPKCS12Zero);

								//
								// set the attributes on the key
								//
								PKCS12BagAttributeCarrier bagAttr = (PKCS12BagAttributeCarrier) privKey;
								String alias = null;
								ASN1OctetString localId = null;

								Enumeration e = b.getBagAttributes()
										.getObjects();
								while (e.hasMoreElements()) {
									ASN1Sequence sq = (ASN1Sequence) e
											.nextElement();
									ASN1ObjectIdentifier aOid = (ASN1ObjectIdentifier) sq
											.getObjectAt(0);
									ASN1Set attrSet = (ASN1Set) sq
											.getObjectAt(1);
									ASN1Primitive attr = null;

									if (attrSet.size() > 0) {
										attr = (ASN1Primitive) attrSet
												.getObjectAt(0);

										ASN1Encodable existing = bagAttr
												.getBagAttribute(aOid);
										if (existing != null) {
											// OK, but the value has to be the
											// same
											if (!existing.toASN1Primitive()
													.equals(attr)) {
												throw new IOException(
														"attempt to add existing attribute with different value");
											}
										} else {
											bagAttr.setBagAttribute(aOid, attr);
										}
									}

									if (aOid.equals(pkcs_9_at_friendlyName)) {
										alias = ((DERBMPString) attr)
												.getString();
										keys.put(alias, privKey);
									} else if (aOid
											.equals(pkcs_9_at_localKeyId)) {
										localId = (ASN1OctetString) attr;
									}
								}

								String name = new String(Hex.encode(localId
										.getOctets()));

								if (alias == null) {
									keys.put(name, privKey);
								} else {
									localIds.put(alias, name);
								}
							} else if (b.getBagId().equals(keyBag)) {
								org.bouncycastle.asn1.pkcs.PrivateKeyInfo kInfo = new org.bouncycastle.asn1.pkcs.PrivateKeyInfo(
										(ASN1Sequence) b.getBagValue());
								System.out.println("kInfo: " + kInfo);
								PrivateKey privKey = BouncyCastleProvider
										.getPrivateKey(kInfo);

								//
								// set the attributes on the key
								//
								PKCS12BagAttributeCarrier bagAttr = (PKCS12BagAttributeCarrier) privKey;
								String alias = null;
								ASN1OctetString localId = null;

								Enumeration e = b.getBagAttributes()
										.getObjects();
								while (e.hasMoreElements()) {
									ASN1Sequence sq = (ASN1Sequence) e
											.nextElement();
									ASN1ObjectIdentifier aOid = (ASN1ObjectIdentifier) sq
											.getObjectAt(0);
									ASN1Set attrSet = (ASN1Set) sq
											.getObjectAt(1);
									ASN1Primitive attr = null;

									if (attrSet.size() > 0) {
										attr = (ASN1Primitive) attrSet
												.getObjectAt(0);

										ASN1Encodable existing = bagAttr
												.getBagAttribute(aOid);
										if (existing != null) {
											// OK, but the value has to be the
											// same
											if (!existing.toASN1Primitive()
													.equals(attr)) {
												throw new IOException(
														"attempt to add existing attribute with different value");
											}
										} else {
											bagAttr.setBagAttribute(aOid, attr);
										}
									}

									if (aOid.equals(pkcs_9_at_friendlyName)) {
										alias = ((DERBMPString) attr)
												.getString();
										keys.put(alias, privKey);
									} else if (aOid
											.equals(pkcs_9_at_localKeyId)) {
										localId = (ASN1OctetString) attr;
									}
								}

								String name = new String(Hex.encode(localId
										.getOctets()));

								if (alias == null) {
									keys.put(name, privKey);
								} else {
									localIds.put(alias, name);
								}
							} else {
								System.out.println("extra in encryptedData "
										+ b.getBagId());
								System.out.println(ASN1Dump.dumpAsString(b));
							}
						}
					} else {
						System.out.println("extra "
								+ c[i].getContentType().getId());
						System.out.println("extra "
								+ ASN1Dump.dumpAsString(c[i].getContent()));
					}
				}
			}

		}

		protected PrivateKey unwrapXXKey(AlgorithmIdentifier algId, byte[] data,
				char[] password, boolean wrongPKCS12Zero) throws IOException {
			String algorithm = algId.getAlgorithm().getId();
			System.out.println(algorithm);
			PKCS12PBEParams pbeParams = PKCS12PBEParams.getInstance(algId
					.getParameters());

			PBEKeySpec pbeSpec = new PBEKeySpec(password);
			PrivateKey out;

			try {
				SecretKeyFactory keyFact = SecretKeyFactory.getInstance(algorithm,
						bcProvider);
				PBEParameterSpec defParams = new PBEParameterSpec(
						pbeParams.getIV(), pbeParams.getIterations().intValue());

				SecretKey k = keyFact.generateSecret(pbeSpec);

				((BCPBEKey) k).setTryWrongPKCS12Zero(wrongPKCS12Zero);

				Cipher cipher = Cipher.getInstance(algorithm, bcProvider);

				cipher.init(Cipher.UNWRAP_MODE, k, defParams);

				// we pass "" as the key algorithm type as it is unknown at this
				// point
				out = (PrivateKey) cipher.unwrap(data, "", Cipher.PRIVATE_KEY);
				
				
				// 다시 decrypt 해서 PrivateKeyInfo를 가져와본다 
				cipher.init(Cipher.DECRYPT_MODE, k, defParams);
				PrivateKeyInfo       in = PrivateKeyInfo.getInstance(cipher.doFinal(data));
				PrivateKey privKey = BouncyCastleProvider.getPrivateKey(in);
				
				System.out.println("Shoud be equal: " + out.equals(privKey));

				ASN1Set set = in.getAttributes();
				Attribute attribute = Attribute.getInstance(set.getObjectAt(0));
				ASN1Encodable rValueAsASNEncodable = attribute.getAttributeValues()[0];
				rvalue = ((DERBitString)rValueAsASNEncodable).getBytes();
			} catch (Exception e) {
				throw new IOException("exception unwrapping private key - "
						+ e.toString());
			}

			return out;
		}

	}


	public static Provider bcProvider = new BouncyCastleProvider();

	private static byte[] calculatePbeMac(ASN1ObjectIdentifier oid,
			byte[] salt, int itCount, char[] password, boolean wrongPkcs12Zero,
			byte[] data) throws Exception {
		SecretKeyFactory keyFact = SecretKeyFactory.getInstance(oid.getId(),
				bcProvider);
		PBEParameterSpec defParams = new PBEParameterSpec(salt, itCount);
		PBEKeySpec pbeSpec = new PBEKeySpec(password);
		BCPBEKey key = (BCPBEKey) keyFact.generateSecret(pbeSpec);
		key.setTryWrongPKCS12Zero(wrongPkcs12Zero);

		Mac mac = Mac.getInstance(oid.getId(), bcProvider);
		mac.init(key, defParams);
		mac.update(data);
		return mac.doFinal();
	}

	private static class IgnoresCaseHashtable {
		@SuppressWarnings("rawtypes")
		private Hashtable orig = new Hashtable();
		@SuppressWarnings("rawtypes")
		private Hashtable keys = new Hashtable();

		@SuppressWarnings("unchecked")
		public void put(String key, Object value) {
			String lower = Strings.toLowerCase(key);
			String k = (String) keys.get(lower);
			if (k != null) {
				orig.remove(k);
			}

			keys.put(lower, key);
			orig.put(key, value);
		}

		@SuppressWarnings({ "rawtypes", "unused" })
		public Enumeration keys() {
			return orig.keys();
		}

		@SuppressWarnings("unused")
		public Object remove(String alias) {
			String k = (String) keys.remove(Strings.toLowerCase(alias));
			if (k == null) {
				return null;
			}

			return orig.remove(k);
		}

		@SuppressWarnings("unused")
		public Object get(String alias) {
			String k = (String) keys.get(Strings.toLowerCase(alias));
			if (k == null) {
				return null;
			}

			return orig.get(k);
		}

		@SuppressWarnings({ "rawtypes", "unused" })
		public Enumeration elements() {
			return orig.elements();
		}
	}
	
}
