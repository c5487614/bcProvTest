package cn.org.hbca.bc;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Locale;
import java.util.Set;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.tsp.TimeStampResp;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.RecipientInfoGenerator;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS12PfxPdu;
import org.bouncycastle.pkcs.PKCS12PfxPduBuilder;
import org.bouncycastle.pkcs.PKCS12SafeBag;
import org.bouncycastle.pkcs.PKCS12SafeBagBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS12SafeBagBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCS12MacCalculatorBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEOutputEncryptorBuilder;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.util.encoders.Base64;

public class Test {

	public static void main(String[] args) throws Exception {
		// TODO Auto-generated method stub
		AESEncrypt();
	}
	private static void envelopTest2()throws Exception{
		Provider provider = new BouncyCastleProvider();
		Security.addProvider(provider);
		
		KeyStore ks = KeyStore.getInstance("PKCS12");
		ks.load(new FileInputStream("Z:/十堰机构测试_加密.pfx"), "11111111".toCharArray());
		PrivateKey rootPrikey = null;
		X509Certificate rootCert = null;
		Enumeration enums = ks.aliases();
		while(enums.hasMoreElements()){
			String keyAlias = (String) enums.nextElement();  
			System.out.println("alias=[" + keyAlias + "]");  
			if(ks.isKeyEntry(keyAlias)){
				System.out.println("isKeyEntry=[" + keyAlias + "]");
				rootPrikey=(PrivateKey)ks.getKey(keyAlias, "11111111".toCharArray());
				
				rootCert = (X509Certificate) ks.getCertificate(keyAlias);
			}
			if(ks.isCertificateEntry(keyAlias)){
				System.out.println("isCertificateEntry=[" + keyAlias + "]");  
			}
		}
		String envelopB64 = "MIIBmAYJKoZIhvcNAQcDoIIBiTCCAYUCAQAxggEpMIIBJQIBADCBjTB5MQswCQYDVQQGEwJDTjEOMAwGA1UECAwFSFVCRUkxDjAMBgNVBAcMBVdVSEFOMTswOQYDVQQKDDJIdWlCZWkgRGlnaXRhbCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgQ2VudGVyIENPLkxURDENMAsGA1UEAwwESEJDQQIQE1xhKfb+ItNhta/KYGm9mzANBgkqgRzPVQGCLQMFAASBgLaAKu3feHzgp+vFi0fbfok/nWrIoJj8YZakpqzSNPOwSB7U6/Jx4RQKr2em78COmQaGMBHMszXOSibGnE6WfRUiH0s2QNby7U+I5PwbGgXW/NQD6R8JaOzbsEYBFkaBqbNDirIVcZGV3bF+VtJzsqZECoZCMmHAnZjlb4kbPae9MFMGCSqGSIb3DQEHATAUBggqhkiG9w0DBwQIp3KRufXjzNKAMHVVYpg/ghBRYhk1LhAl9xC/ooC55zjkOnx8eOgHtWJDQmF8M4A/hSHKHdt2m8GU5Q==";
		envelopB64 = "MIIBmAYJKoZIhvcNAQcDoIIBiTCCAYUCAQAxggEpMIIBJQIBADCBjTB5MQswCQYDVQQGEwJDTjEOMAwGA1UECAwFSFVCRUkxDjAMBgNVBAcMBVdVSEFOMTswOQYDVQQKDDJIdWlCZWkgRGlnaXRhbCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgQ2VudGVyIENPLkxURDENMAsGA1UEAwwESEJDQQIQE1xhKfb+ItNhta/KYGm9mzANBgkqhkiG9w0BAQEFAASBgIx8Zeu6syqtPSNcKVBcasyrp3QSBvhOHj8spq8quGpR60t4TcDbmiozqgwgYtuzn2ZRP4BRcPd0RNb4JJRYIYrjJoSsqoeEyNZGUHtQuwAq1gF5BfpWHMdlIwpo3zMJqvGdI3qmjQqsmEPo1gs8VjpnDK9fXlWIs7ZVc05jh4VdMFMGCSqGSIb3DQEHATAUBggqhkiG9w0DBwQILLKxGZ1xt1KAMAeAWD7uN0K9RpZU+1moiXyYoFhhj+nMZZWakPJmWy6RQywe5xdxVvlkMWyhoEQuKw==";
		Base64 base64 = new Base64();
		CMSEnvelopedData enveloped = new CMSEnvelopedData(base64.decode(envelopB64));
		RecipientInformationStore recipients = enveloped.getRecipientInfos();
		Collection c = recipients.getRecipients();
		Iterator it = c.iterator();
		if (it.hasNext()) {
			RecipientInformation recipient = (RecipientInformation) it.next();
			byte[] recData = recipient.getContent(new JceKeyTransEnvelopedRecipient(rootPrikey).setProvider("BC"));
			System.out.println(new String(recData));
		}
	}
	private static void envelopTest()throws Exception{
		Provider provider = new BouncyCastleProvider();
		Security.addProvider(provider);
		
		KeyStore ks = KeyStore.getInstance("PKCS12");
		ks.load(new FileInputStream("F:/tsaserver.pfx"), "11111111".toCharArray());
		PrivateKey rootPrikey = null;
		X509Certificate rootCert = null;
		Enumeration enums = ks.aliases();
		while(enums.hasMoreElements()){
			String keyAlias = (String) enums.nextElement();  
			System.out.println("alias=[" + keyAlias + "]");  
			if(ks.isKeyEntry(keyAlias)){
				System.out.println("isKeyEntry=[" + keyAlias + "]");
				rootPrikey=(PrivateKey)ks.getKey(keyAlias, "11111111".toCharArray());
				
				rootCert = (X509Certificate) ks.getCertificate(keyAlias);
			}
			if(ks.isCertificateEntry(keyAlias)){
				System.out.println("isCertificateEntry=[" + keyAlias + "]");  
			}
		}
		
		CMSTypedData msg = new CMSProcessableByteArray("Hello World!".getBytes());

		CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
		gen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(rootCert));
		
		CMSEnvelopedData enveloped = gen.generate(msg, new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC).build());
		
		Base64 base64 = new Base64();
		System.out.println(new String(base64.encode(enveloped.getEncoded())));
		RecipientInformationStore recipients = enveloped.getRecipientInfos();
		Collection c = recipients.getRecipients();
		Iterator it = c.iterator();
		if (it.hasNext()) {
			RecipientInformation recipient = (RecipientInformation) it.next();
			byte[] recData = recipient.getContent(new JceKeyTransEnvelopedRecipient(rootPrikey).setProvider("BC"));
			System.out.println(new String(recData));
		}
	}
	private static void generateP12File() throws Exception{
		Provider provider = new BouncyCastleProvider();
		Security.addProvider(provider);
		
		KeyStore ks = KeyStore.getInstance("PKCS12");
		ks.load(new FileInputStream("F:/tsaserver.pfx"), "11111111".toCharArray());
		PrivateKey rootPrikey = null;
		X509Certificate rootCert = null;
		Enumeration enums = ks.aliases();
		while(enums.hasMoreElements()){
			String keyAlias = (String) enums.nextElement();  
			System.out.println("alias=[" + keyAlias + "]");  
			if(ks.isKeyEntry(keyAlias)){
				System.out.println("isKeyEntry=[" + keyAlias + "]");
				rootPrikey=(PrivateKey)ks.getKey(keyAlias, "11111111".toCharArray());
				
				rootCert = (X509Certificate) ks.getCertificate(keyAlias);
			}
			if(ks.isCertificateEntry(keyAlias)){
				System.out.println("isCertificateEntry=[" + keyAlias + "]");  
			}
		}
		
		//initial key pair
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
	    kpg.initialize(1024);
	    KeyPair keyPair = kpg.genKeyPair();

	    X509v3CertificateBuilder v3CertGen = new X509v3CertificateBuilder(new X500Name("CN=HBCA,O=Hubei Digital Certificate Authority Center CO Ltd.,L=Wuhan,C=CN"), new BigInteger("123"), 
		new Date(System.currentTimeMillis()), new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)), 
		Locale.CHINA, new X500Name("CN=TEST,C=CN"),SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()));
	    //add extention
	    DigestCalculator digCalc = new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));
	    X509ExtensionUtils x509ExtUtil = new X509ExtensionUtils(digCalc);
	    //issuer key identifier
	    X509CertificateHolder rootCertHolder = new X509CertificateHolder(rootCert.getEncoded());
	    AuthorityKeyIdentifier authorityKeyIdentifier = x509ExtUtil.createAuthorityKeyIdentifier(rootCertHolder);
	    v3CertGen.addExtension(Extension.authorityKeyIdentifier, false, authorityKeyIdentifier.getEncoded());
	    //user key identifier
	    SubjectPublicKeyInfo subjPubKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
	    v3CertGen.addExtension(Extension.subjectKeyIdentifier, false, x509ExtUtil.createSubjectKeyIdentifier(subjPubKeyInfo));
	    //Key Usage
	    v3CertGen.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.digitalSignature|KeyUsage.nonRepudiation));
	    //Basic Constraints
	    v3CertGen.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
	    //Certificate Policies
	    PolicyInformation[] certPolicies = new PolicyInformation[2];
	    certPolicies[0] = new PolicyInformation(new ASN1ObjectIdentifier("2.16.840.1.101.2.1.11.5"));
	    certPolicies[1] = new PolicyInformation(new ASN1ObjectIdentifier("2.16.840.1.101.2.1.11.18"));
	    v3CertGen.addExtension(Extension.certificatePolicies, false, new CertificatePolicies(certPolicies));
	    //self define oid
	    ASN1ObjectIdentifier asn1oid = new ASN1ObjectIdentifier("1.2.3.4");
	    Extension ext = new Extension(asn1oid, false, "CCH".getBytes());
	    v3CertGen.addExtension(new ASN1ObjectIdentifier("2.4.16.11.7.1"), false, ext.getEncoded());
	    
	    ContentSigner sigGen = new JcaContentSignerBuilder("SHA1WithRSAEncryption").setProvider("BC").build(rootPrikey);
	    
	    byte[] certBytes = v3CertGen.build(sigGen).getEncoded();
	    
	    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
	    X509Certificate certificate = (X509Certificate)certificateFactory.generateCertificate(new ByteArrayInputStream(certBytes));
	    FileOutputStream fs = new FileOutputStream("F:/test.cer");
	    fs.write(certBytes);
	    fs.close();

	    FileInputStream fs2 = new FileInputStream("F:/test.cer");
	    Certificate c = certificateFactory.generateCertificate(fs2);
	    
	    FileOutputStream fs1 = new FileOutputStream("F:/test1.p12");
	    createPKCS12File(fs1,keyPair.getPrivate(),new Certificate[]{c,c,c});
	}
	private static void createPKCS12File(OutputStream pfxOut, PrivateKey key, Certificate[] chain)
	        throws Exception
	    {
	        OutputEncryptor encOut = new JcePKCSPBEOutputEncryptorBuilder(NISTObjectIdentifiers.id_aes256_CBC).setProvider("BC").build("11111111".toCharArray());

//	        PKCS12SafeBagBuilder taCertBagBuilder = new JcaPKCS12SafeBagBuilder((X509Certificate)chain[2]);
//
//	        taCertBagBuilder.addBagAttribute(PKCS12SafeBag.friendlyNameAttribute, new DERBMPString("Bouncy Primary Certificate"));
//
//	        PKCS12SafeBagBuilder caCertBagBuilder = new JcaPKCS12SafeBagBuilder((X509Certificate)chain[1]);
//
//	        caCertBagBuilder.addBagAttribute(PKCS12SafeBag.friendlyNameAttribute, new DERBMPString("Bouncy Intermediate Certificate"));

	        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
	        PKCS12SafeBagBuilder eeCertBagBuilder = new JcaPKCS12SafeBagBuilder((X509Certificate)chain[0]);

//	        eeCertBagBuilder.addBagAttribute(PKCS12SafeBag.friendlyNameAttribute, new DERBMPString("Eric's Key"));
//	        SubjectKeyIdentifier pubKeyId = extUtils.createSubjectKeyIdentifier(chain[0].getPublicKey());
//	        eeCertBagBuilder.addBagAttribute(PKCS12SafeBag.localKeyIdAttribute, pubKeyId);

//	        PKCS12SafeBagBuilder keyBagBuilder = new JcaPKCS12SafeBagBuilder(key, encOut);
	        PKCS12SafeBagBuilder keyBagBuilder = new JcaPKCS12SafeBagBuilder(key);

//	        keyBagBuilder.addBagAttribute(PKCS12SafeBag.friendlyNameAttribute, new DERBMPString("Eric's Key"));
//	        keyBagBuilder.addBagAttribute(PKCS12SafeBag.localKeyIdAttribute, pubKeyId);

	        PKCS12PfxPduBuilder builder = new PKCS12PfxPduBuilder();

	        builder.addData(keyBagBuilder.build());

//	        builder.addEncryptedData(new JcePKCSPBEOutputEncryptorBuilder(PKCSObjectIdentifiers.pbeWithSHAAnd128BitRC2_CBC).setProvider("BC").build("11111111".toCharArray()), new PKCS12SafeBag[]{eeCertBagBuilder.build(), caCertBagBuilder.build(), taCertBagBuilder.build()});

//	        builder.addEncryptedData(new JcePKCSPBEOutputEncryptorBuilder(PKCSObjectIdentifiers.pbeWithSHAAnd128BitRC2_CBC).setProvider("BC").build("11111111".toCharArray()), new PKCS12SafeBag[]{eeCertBagBuilder.build()});
	        builder.addData(eeCertBagBuilder.build());
	        PKCS12PfxPdu pfx = builder.build(new JcePKCS12MacCalculatorBuilder(NISTObjectIdentifiers.id_sha256), "11111111".toCharArray());

	        // make sure we don't include indefinite length encoding
//	        pfxOut.write(pfx.getEncoded());
	        pfxOut.write(pfx.getEncoded(ASN1Encoding.DL));

	        pfxOut.close();
	    }
	private static void TimeStampTest() throws Exception {
		Base64 base64 = new Base64();
		String TSA_URL = "http://tsa.wosign.com/rfc3161";
		String data = "HBCA20160614";
		byte[] digest = MessageDigest.getInstance("SHA1").digest(data.getBytes());
		TimeStampRequestGenerator reqgen = new TimeStampRequestGenerator();
        TimeStampRequest req = reqgen.generate(TSPAlgorithms.SHA1, digest);
        byte[] request = req.getEncoded();
        
        //System.out.println(new String(base64.encode(digest)));
        System.out.println(digest.length);
        URL url = new URL(TSA_URL);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();

        con.setDoOutput(true);
        con.setDoInput(true);
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-Type", "application/timestamp-query");
        con.setRequestProperty("Content-length", String.valueOf(request.length));
        OutputStream out = null;
        out = con.getOutputStream();
        out.write(request);
        out.flush();
        if (con.getResponseCode() != HttpURLConnection.HTTP_OK) {
            throw new IOException("Received HTTP error: " + con.getResponseCode() + " - " + con.getResponseMessage());
        }
        
        InputStream in = con.getInputStream();
        TimeStampResp resp = TimeStampResp.getInstance(new ASN1InputStream(in).readObject());
        TimeStampResponse response = new TimeStampResponse(resp);
        response.validate(req);
        System.out.println(response.getTimeStampToken().getSID().getIssuer());
        System.out.println(response.getTimeStampToken().getTimeStampInfo().getGenTime());
        System.out.println(new String(base64.encode(response.getEncoded())));
	}
	private static void AESEncrypt() throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException{
		byte[] myIV = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
		byte[] keys = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
		Security.addProvider(new BouncyCastleProvider());
		KeyGenerator kg = KeyGenerator.getInstance("AES","BC");
		kg.init(256);
		
		SecretKey secretKey=new SecretKeySpec(keys,"AES");
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
		cipher.init(Cipher.ENCRYPT_MODE, secretKey,new IvParameterSpec(myIV));
		
		byte[] encryptData = cipher.doFinal("HBCA20160530".getBytes());
		Base64 base64 = new Base64();
		System.out.println(new String(base64.encode(encryptData)));
		
		cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
		cipher.init(Cipher.DECRYPT_MODE, secretKey,new IvParameterSpec(myIV));
		byte[] data = cipher.doFinal(encryptData);
		System.out.println(new String(data));
	}
	private static void asn1Explain() throws IOException{
		ASN1InputStream ais = new ASN1InputStream(new FileInputStream(new File("F:/cch.cer")));
	    ASN1Sequence asnSeq = (ASN1Sequence) ais.readObject();
	    Enumeration enum1 = asnSeq.getObjects();
	    Util.enumASN1Object(enum1);
	    ais.close();
	}
	private static void readCert() throws FileNotFoundException, CertificateException{
		FileInputStream fis=new FileInputStream("F:/cch.cer");
		CertificateFactory factory = CertificateFactory.getInstance("X.509");
		X509Certificate cert = (X509Certificate) factory.generateCertificate(fis);
		Set<String> critSet = cert.getCriticalExtensionOIDs();
		 if (critSet != null && !critSet.isEmpty()) {
		     System.out.println("Set of critical extensions:");
		     for (String oid : critSet) {
		         System.out.println(oid);
		     }
		 }

		System.out.println(cert.getSubjectDN().getName());
	}
	private static void signDataVerify() throws NoSuchAlgorithmException, NoSuchProviderException, CertificateException, FileNotFoundException, IOException, Exception{
		Provider provider = new BouncyCastleProvider();
		Security.addProvider(provider);
		String data = "ChunhuiChen";
		KeyStore ks = KeyStore.getInstance("PKCS12");
		ks.load(new FileInputStream("F:/十堰机构测试_签名.pfx"), "11111111".toCharArray());
		Enumeration enums = ks.aliases();
		while(enums.hasMoreElements()){
			String keyAlias = (String) enums.nextElement();  
			System.out.println("alias=[" + keyAlias + "]");  
			if(ks.isKeyEntry(keyAlias)){
				System.out.println("isKeyEntry=[" + keyAlias + "]");
				PrivateKey prikey=(PrivateKey)ks.getKey(keyAlias, "11111111".toCharArray());
				
				Signature signature = Signature.getInstance("SHA1WithRSA", "BC");
				signature.initSign(prikey);
		        signature.update(data.getBytes());
		        byte[] signedResult = signature.sign();
		        System.out.println(new String(Base64.encode(signedResult)));  
				
		        PublicKey pubKey = ks.getCertificate(keyAlias).getPublicKey();
		        signature.initVerify(pubKey);
		        signature.update(data.getBytes());
		        boolean bSucc = signature.verify(signedResult);
		        System.out.println(bSucc);
		        
			}
			if(ks.isCertificateEntry(keyAlias)){
				System.out.println("isCertificateEntry=[" + keyAlias + "]");  
			}
		}
		
	}
	private static void p7Sign() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, UnrecoverableKeyException, NoSuchProviderException, InvalidKeyException, CMSException, SignatureException{
		/*
		Provider provider = new BouncyCastleProvider();
		Security.addProvider(provider);
		String data = "ChunhuiChen";
		KeyStore ks = KeyStore.getInstance("PKCS12");
		ks.load(new FileInputStream("F:/十堰机构测试_签名.pfx"), "11111111".toCharArray());
		Enumeration enums = ks.aliases();
		while(enums.hasMoreElements()){
			String keyAlias = (String) enums.nextElement();  
			System.out.println("alias=[" + keyAlias + "]");  
			if(ks.isKeyEntry(keyAlias)){
				System.out.println("isKeyEntry=[" + keyAlias + "]");
				PrivateKey prikey=(PrivateKey)ks.getKey(keyAlias, "11111111".toCharArray());
				
				Signature signature = Signature.getInstance("SHA1WithRSA", "BC");
				signature.initSign(prikey);
		        signature.update(data.getBytes());
		        X509Certificate cert = (X509Certificate) ks.getCertificate(keyAlias);
		        List certList = new ArrayList();
		        CMSTypedData msg = new CMSProcessableByteArray(signature.sign());
		        certList.add(cert);
		        Store certs = new JcaCertStore(certList);
		        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
		        ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(prikey);
		        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()).build(sha1Signer, cert));
		        gen.addCertificates(certs);
		        CMSSignedData sigData = gen.generate(msg, false);
		        String result = new String(Base64.encode(sigData.getEncoded()));
		        System.out.println(result);
		        
				//System.out.println(ks.getCertificate(keyAlias).getPublicKey().getAlgorithm());
//				System.out.println(ks.getCertificateChain(keyAlias));
//				Certificate cert = ks.getCertificate(keyAlias);
//				X509CertificateHolder certificateHolder = new X509CertificateHolder(cert.getEncoded());
//				CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
//				ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(prikey);
//				SignerInfoGenerator signerInfoGen = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()).build(sha1Signer, certificateHolder);
//				List certList = new ArrayList();
//				certList.add(certificateHolder);
//				Store certs = new JcaCertStore(certList);
//				gen.addCertificates(certs);
//				gen.addSignerInfoGenerator(signerInfoGen);
//				CMSTypedData msg = new CMSProcessableByteArray("ChunhuiChen".getBytes()); //Data to sign
//				CMSSignedData sigData = gen.generate(msg, true);
//				String result = new String(Base64.encode(sigData.getEncoded()));
//				
//				
//				System.out.println(result);
			}
			if(ks.isCertificateEntry(keyAlias)){
				System.out.println("isCertificateEntry=[" + keyAlias + "]");  
			}
		}*/
	}
	private static void getKeyAlias() throws NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, KeyStoreException{
		Provider provider = new BouncyCastleProvider();
		Security.addProvider(provider);
		KeyStore ks = KeyStore.getInstance("PKCS12");
		ks.load(new FileInputStream("F:/十堰机构测试_签名.pfx"), "11111111".toCharArray());
		Enumeration enums = ks.aliases();
		while(enums.hasMoreElements()){
			String keyAlias = (String) enums.nextElement();  
			System.out.println("alias=[" + keyAlias + "]");  
		}
	}
	private static void sha256Digest(){
		byte[] datas = "ChunhuiChen".getBytes();
		Digest digest = new SHA256Digest();
        digest.update(datas,0,datas.length); 
        byte[] out = new byte[digest.getDigestSize()]; 
        digest.doFinal(out, 0);
        System.out.println(Util.getHexString(out));
	}
	private static void sha1Digest(){
		byte[] datas = "ChunhuiChen".getBytes();
		Digest digest = new SHA1Digest();
        digest.update(datas,0,datas.length); 
        byte[] out = new byte[digest.getDigestSize()]; 
        digest.doFinal(out, 0);
        System.out.println(Util.getHexString(out));
	}

}
