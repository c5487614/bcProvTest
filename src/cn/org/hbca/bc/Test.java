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
import java.security.PublicKey;
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

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

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
import org.bouncycastle.jcajce.provider.symmetric.AES.KeyGen;
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
import org.bouncycastle.util.encoders.Base64Encoder;

public class Test {

	public static void main(String[] args) throws Exception {
		// TODO Auto-generated method stub
		//signDataVerify();
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
