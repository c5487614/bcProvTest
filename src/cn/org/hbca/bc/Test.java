package cn.org.hbca.bc;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DEREnumerated;
import org.bouncycastle.asn1.DERGeneralString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTags;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;

public class Test {

	public static void main(String[] args) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, UnrecoverableKeyException, OperatorCreationException, CMSException, NoSuchProviderException, SignatureException, InvalidKeyException {
		// TODO Auto-generated method stub
		ASN1InputStream ais = new ASN1InputStream(new FileInputStream(new File("F:/cch.cer")));
	    ASN1Sequence asnSeq = (ASN1Sequence) ais.readObject();
	    Enumeration enum1 = asnSeq.getObjects();
	    Util.enumASN1Object(enum1);
	}
	private static void asn1Explain() throws IOException{
		String data = "MIIDyTCCAzKgAwIBAgIQFMmwMc+3V8BIwCaNTu2MBjANBgkqhkiG9w0BAQUFADB5MQswCQYDVQQGEwJDTjEOMAwGA1UECAwFSFVCRUkxDjAMBgNVBAcMBVdVSEFOMTswOQYDVQQKDDJIdWlCZWkgRGlnaXRhbCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgQ2VudGVyIENPLkxURDENMAsGA1UEAwwESEJDQTAeFw0xNjA0MjUwODAwMTRaFw0xNzA0MjUwODAwMTRaMFAxCzAJBgNVBAYTAkNOMQ8wDQYDVQQIDAbmuZbljJcxDzANBgNVBAcMBumaj+W3njEfMB0GA1UEAwwW6ZmI5pil6L6J5py65p6E5rWL6K+VMTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAwhcdmA2w1WVdef5+ZspB+n2TJgv3DcuV/2d7BChed62C1+kYfW42o5mV7IwIP+RTgYoTgfqekAzf2fRTPJAN75QPK76XjC9ykKVLVwNLooqbpjYlnwLJqR3ymF4QgyM+ZgGq4TcWSxRJMRY8OFeOgwN/viq6uoRvrhFM0hk/5QECAwEAAaOCAXkwggF1MB8GA1UdIwQYMBaAFFt6x6jV3alaHcJPyZOgFeRrksQ7MAwGA1UdEwQFMAMBAQAwEAYFVBALBwEEBwwFKjYzQiowgfAGA1UdHwSB6DCB5TA2oDSgMqQwMC4xCzAJBgNVBAYTAkNOMRAwDgYDVQQLDAdBREQxQ1JMMQ0wCwYDVQQDDARjcmw5MDGgL6AthitodHRwOi8vd3d3LmhiY2Eub3JnLmNuL2NybF9yc2ExMDI0L2NybDkuY3JsMHigdqB0hnJsZGFwOi8vMjIxLjIzMi4yMjQuNzQ6MTM4OS9DTj1jcmw5LE9VPUFERDFDUkwsQz1DTj9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Y2xhc3M9Y1JMRGlzdHJpYnV0aW9uUG9pbnQwEwYFKlYLBwMEChMINDQ0NDQ0NDQwCwYDVR0PBAQDAgbAMB0GA1UdDgQWBBSkefovysActwRgX2J+zU3RoZ4EcDANBgkqhkiG9w0BAQUFAAOBgQAFcMvWJcU4DChyfMVciJr3qMOTQxS2sXYYb1m5ob9M8OLdPEBH6Sr6mq3Jjez3K0IWBERr4bGXLefD5s860ra2tqOupV7k51Ceg/2gc2ybiChX41F8/txshFCMTTpe4YC7rQU0Wz8fxA8m/wzy0xWoKAGC9ikt40cpuNo9xP1GTg==";
		ByteArrayInputStream inStream = new ByteArrayInputStream(data.getBytes());
	    ASN1InputStream asnInputStream = new ASN1InputStream(inStream);
//	    DERApplicationSpecific derApp = (DERApplicationSpecific)asnInputStream.readObject();
//	    DERGeneralString asn1Enum = (DERGeneralString) derApp.getObject(BERTags.GENERAL_STRING);
//	    Base64.decode()
	    
//	    ASN1InputStream ais = new ASN1InputStream(new FileInputStream(new File("F:/cch.cer")));
//	    while (ais.available() > 0) {
//	        ASN1Primitive obj = ais.readObject();
//	        System.out.println(ASN1Dump.dumpAsString(obj, true));
//	    }
	    
	    ASN1InputStream ais = new ASN1InputStream(new FileInputStream(new File("F:/cch.cer")));
	    ASN1Sequence asnSeq = (ASN1Sequence) ais.readObject();
	    Enumeration enum1 = asnSeq.getObjects();
	    while(enum1.hasMoreElements()){
	    	System.out.println("i");
	    	Object obj = enum1.nextElement();
	    	if(obj instanceof ASN1Sequence){
	    		ASN1Sequence asn1Seq = (ASN1Sequence)obj;
	    		Enumeration enum2 = asn1Seq.getObjects();
	    		while(enum2.hasMoreElements()){
	    			Object obj2 = enum2.nextElement();
	    			if(obj2 instanceof ASN1Sequence){
	    				ASN1Sequence asn1Seq2 = (ASN1Sequence)obj2;
	    				Enumeration enum3 = asn1Seq2.getObjects();
	    				while(enum3.hasMoreElements()){
	    					Object obj3 = enum3.nextElement();
	    					if(obj3 instanceof ASN1ObjectIdentifier){
	    						ASN1ObjectIdentifier asn1ObjectIndentifier = (ASN1ObjectIdentifier)obj3;
	    						String str = new String(asn1ObjectIndentifier.getId());
	    						System.out.println(str);
	    					}
	    				}
	    			}
	    		}
	    	}else{
	    		
	    	}
	    }
	    inStream.close();
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
	private static void p7Sign() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, UnrecoverableKeyException, NoSuchProviderException, InvalidKeyException, OperatorCreationException, CMSException, SignatureException{
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
		}
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
