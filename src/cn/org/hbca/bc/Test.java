package cn.org.hbca.bc;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
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
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.Set;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.tsp.TimeStampResp;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenGenerator;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;

public class Test {

	public static void main(String[] args) throws Exception {
		// TODO Auto-generated method stub
		//signDataVerify();
//		TimeStampTest();
		String dataB64 = "MEMCAQEwMTANBglghkgBZQMEAgEFAAQgcWC905SZZOq+1f53M3anm1HIIv3bJ7pwYJUGrbFqZnoCCMewWlJhY/kOAQH/";
		Base64 base64 = new Base64();
		ASN1InputStream ais = new ASN1InputStream(base64.decode(dataB64));
	    ASN1Sequence asnSeq = (ASN1Sequence) ais.readObject();
	    Enumeration enum1 = asnSeq.getObjects();
	    //byte 
	    byte[] data = getHashData(enum1);
	    System.out.println(data.length);
	    System.out.println(Util.bytesToHexString(data));
	    //get hexStr
	    enum1 = asnSeq.getObjects();
	    //byte 
	    String hashMethod = getHashMethod(enum1);
	    System.out.println(hashMethod);
	    //Util.enumASN1Object(enum1);
	    ais.close();
	}
	private static ASN1Integer getNounce(Enumeration enum1) {
		// int
		Object asn1Object = enum1.nextElement();
		// seq
		ASN1Sequence asnSeq1 = (ASN1Sequence) enum1.nextElement();
		// nounce
		
		ASN1Integer asn1Int = (ASN1Integer) enum1.nextElement();;
		
		return asn1Int;
	}
	private static String getHashMethod(Enumeration enum1){
		Object asn1Object = enum1.nextElement();
		ASN1Sequence asnSeq1 = (ASN1Sequence) enum1.nextElement();
		enum1 = asnSeq1.getObjects();
		asnSeq1 = (ASN1Sequence) enum1.nextElement();
		enum1 = asnSeq1.getObjects();

		ASN1ObjectIdentifier asn1ObjectIndentifier = (ASN1ObjectIdentifier) enum1.nextElement();
		StringBuffer sb = new StringBuffer();
		try {
			
			sb.append(new String(asn1ObjectIndentifier.getEncoded()));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		System.out.println(sb.toString());
		System.out.println(asn1ObjectIndentifier.getId());
		
		if("2.16.840.1.101.3.4.2.1".equals(sb.toString())){
			return "SHA256";
		}else if("1.3.14.3.2.26".equals(sb.toString())){
			return "SHA1";
		}else{
			return "SHA1";
		}
		
//		return sb.toString();
	}
	private static byte[] getHashData(Enumeration enum1){
		//int
		Object asn1Object = enum1.nextElement();
    	//seq
		ASN1Sequence asnSeq1 = (ASN1Sequence) enum1.nextElement();
		//seq hash
    	enum1 = asnSeq1.getObjects();
    	asnSeq1 = (ASN1Sequence) enum1.nextElement();
    	
    	DEROctetString derOctetStr = (DEROctetString) enum1.nextElement();
    	String hexStr = derOctetStr.toString().replace("#", "");
    	return derOctetStr.getOctets();
		//return Util.hexStringToByte(hexStr);
	}
	private static void TimeStampTest3()throws Exception {
		Provider provider = new BouncyCastleProvider();
		Security.addProvider(provider);
		Base64 base64 = new Base64();
		String TSA_URL = "http://timestamp.wosign.com/rfc3161";
		String data = "HBCA20160614";
		byte[] digest = MessageDigest.getInstance("SHA1").digest(data.getBytes());
		TimeStampRequestGenerator reqgen = new TimeStampRequestGenerator();
        TimeStampRequest req = reqgen.generate(TSPAlgorithms.SHA1, digest);
        //byte[] request = req.getEncoded();
        
        PrivateKey privateKey = null;
        X509Certificate cert = null;
        
        KeyStore ks = KeyStore.getInstance("PKCS12");
		ks.load(new FileInputStream("F:/tsaserver.pfx"), "11111111".toCharArray());
		Enumeration enums = ks.aliases();
		while(enums.hasMoreElements()){
			String keyAlias = (String) enums.nextElement();  
			System.out.println("alias=[" + keyAlias + "]");  
			if(ks.isKeyEntry(keyAlias)){
				System.out.println("isKeyEntry=[" + keyAlias + "]");
				privateKey = (PrivateKey)ks.getKey(keyAlias, "11111111".toCharArray());
				cert = (X509Certificate) ks.getCertificate(keyAlias);
			}
			if(ks.isCertificateEntry(keyAlias)){
				System.out.println("isCertificateEntry=[" + keyAlias + "]");  
			}
		}
		JcaDigestCalculatorProviderBuilder builder = new JcaDigestCalculatorProviderBuilder();
		
		DigestCalculator dgCalc =  builder.setProvider("BC").build().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));
		ContentSigner signer = new JcaContentSignerBuilder("SHA1withRSA").build(privateKey);
		
		
		DigestCalculatorProvider dcp = builder.build();
		JcaSignerInfoGeneratorBuilder jcaSIGB = new JcaSignerInfoGeneratorBuilder(dcp);
		SignerInfoGenerator siGen = jcaSIGB.build(signer, cert);
		ASN1ObjectIdentifier policy = new ASN1ObjectIdentifier("1.2.3.4.5.6"); // Replace by your timestamping policy OID
		TimeStampTokenGenerator tstGen = new TimeStampTokenGenerator(siGen, dgCalc, policy);
		/* Set the parameters e.g. set the accuracy or include the signing certificate */
		TimeStampToken tst = tstGen.generate(req, new BigInteger("23"), new Date());
		byte[] encoding = tst.getEncoded();
		
		TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tstGen, TSPAlgorithms.ALLOWED);
		TimeStampResponse tsResp = tsRespGen.generate(req, new BigInteger("23"), new Date());
		tsResp = new TimeStampResponse(tsResp.getEncoded());
		
		System.out.println(tsResp.getStatusString());
		System.out.println(tsResp.getTimeStampToken().getTimeStampInfo().getGenTime());
		System.out.println(new String(base64.encode(tsResp.getEncoded())));
		System.out.println(new String(base64.encode(req.getEncoded())));
	}
	private static void TimeStampTest2()throws Exception {
		Provider provider = new BouncyCastleProvider();
		Security.addProvider(provider);
		Base64 base64 = new Base64();
		String TSA_URL = "http://timestamp.wosign.com/rfc3161";
		String data = "HBCA20160614";
		byte[] digest = MessageDigest.getInstance("SHA1").digest(data.getBytes());
		TimeStampRequestGenerator reqgen = new TimeStampRequestGenerator();
        TimeStampRequest req = reqgen.generate(TSPAlgorithms.SHA1, digest);
        //byte[] request = req.getEncoded();
        
        PrivateKey privateKey = null;
        X509Certificate cert = null;
        
        KeyStore ks = KeyStore.getInstance("PKCS12");
		ks.load(new FileInputStream("F:/tsaserver.pfx"), "11111111".toCharArray());
		Enumeration enums = ks.aliases();
		while(enums.hasMoreElements()){
			String keyAlias = (String) enums.nextElement();  
			System.out.println("alias=[" + keyAlias + "]");  
			if(ks.isKeyEntry(keyAlias)){
				System.out.println("isKeyEntry=[" + keyAlias + "]");
				privateKey = (PrivateKey)ks.getKey(keyAlias, "11111111".toCharArray());
				cert = (X509Certificate) ks.getCertificate(keyAlias);
			}
			if(ks.isCertificateEntry(keyAlias)){
				System.out.println("isCertificateEntry=[" + keyAlias + "]");  
			}
		}
		System.out.println(cert.getSubjectDN().toString());
		
		AlgorithmIdentifier sha1withRSA = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1withRSA");
//		AlgorithmIdentifier digestAlgorithmIdentifier = new DefaultDigestAlgorithmIdentifierFinder().find(sha1withRSA.getAlgorithm().getId());
		
		JcaDigestCalculatorProviderBuilder builder = new JcaDigestCalculatorProviderBuilder();
		DigestCalculator dgCalc =  builder.setProvider("BC").build().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));
		ContentSigner signer = new JcaContentSignerBuilder("SHA1withRSA").build(privateKey);
	
		DigestCalculatorProvider dcp = builder.build();
		JcaSignerInfoGeneratorBuilder jcaSIGB = new JcaSignerInfoGeneratorBuilder(dcp);
		SignerInfoGenerator siGen = jcaSIGB.build(signer, cert);
		Extension ext = siGen.getAssociatedCertificate().getExtension(Extension.extendedKeyUsage);

		System.out.println(ext.getExtnId().getId());
        System.out.println(ext.isCritical());
        ExtendedKeyUsage extKey = ExtendedKeyUsage.getInstance(ext.getParsedValue());

		ASN1ObjectIdentifier policy = new ASN1ObjectIdentifier("2.4.16.11.7.1"); // Replace by your timestamping policy OID
		//TimeStampTokenGenerator tstGen = new TimeStampTokenGenerator(siGen, dgCalc, policy);
		TimeStampTokenGenerator tstGen = new TimeStampTokenGenerator(
                new JcaSimpleSignerInfoGeneratorBuilder().build("SHA1withRSA", privateKey, cert), dgCalc, new ASN1ObjectIdentifier("1.2"));
		
		ArrayList<X509Certificate> certList = new ArrayList<X509Certificate>();
        certList.add(cert);
        JcaCertStore certs = new JcaCertStore(certList);
        
        tstGen.addAttributeCertificates(certs);
		tstGen.addCertificates(certs);
		tstGen.addCRLs(certs);
		/* Set the parameters e.g. set the accuracy or include the signing certificate */
		
		//TimeStampToken tst = tstGen.generate(req, new BigInteger("13"), new Date());
		
		TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tstGen, TSPAlgorithms.ALLOWED);
		TimeStampResponse tsResp = tsRespGen.generate(req, new BigInteger("23"), new Date());
		tsResp = new TimeStampResponse(tsResp.getEncoded());

		System.out.println(tsResp.getStatusString());
		System.out.println(tsResp.getTimeStampToken().getTimeStampInfo().getGenTime());
		
		System.out.println(new String(base64.encode(tsResp.getEncoded())));
		System.out.println(new String(base64.encode(req.getEncoded())));
	}
	private static void TimeStampTest() throws Exception {
		Base64 base64 = new Base64();
		String TSA_URL = "http://timestamp.wosign.com/rfc3161";
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
