package cn.org.hbca.bc;

import java.io.IOException;
import java.util.Enumeration;
import java.util.Locale;

<<<<<<< HEAD
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Generator;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DEROctetString;

=======
>>>>>>> 6ea783ac2bbc5a52429662a1068cdb9e3493ce2c
public class Util {

	public static byte[] hexStringToByte(String hex) {
		int len = (hex.length() / 2);
		byte[] result = new byte[len];
		char[] achar = hex.toCharArray();
		for (int i = 0; i < len; i++) {
			int pos = i * 2;
			result[i] = (byte) (toByte(achar[pos]) << 4 | toByte(achar[pos + 1]));
		}
		return result;
	}
	private static byte toByte(char c) {
		byte b = (byte) "0123456789ABCDEF".indexOf(c);
		return b;
	}
	public static String bytesToHexString(byte[] src) {
		StringBuilder stringBuilder = new StringBuilder("");  
	    if (src == null || src.length <= 0) {  
	        return null;  
	    }  
	    for (int i = 0; i < src.length; i++) {  
	        int v = src[i] & 0xFF;  
	        String hv = Integer.toHexString(v);  
	        if (hv.length() < 2) {  
	            stringBuilder.append(0);  
	        }  
	        stringBuilder.append(hv);  
	    }  
	    return stringBuilder.toString(); 
	}
	public static String getHexString(byte[] data){
		if(data==null||data.length==0){
			return "";
		}
		StringBuffer sb = new StringBuffer();
		for(byte b : data){
			String hexStr = Integer.toHexString(b&0xff).toUpperCase();
			//String hexStr = Integer.toHexString(b&0xff).toLowerCase();
			//hexStr = hexStr.subSequence(6, 8).toString();
			if(hexStr.length()==1){
				hexStr = "0" + hexStr;
			}
			sb.append(hexStr);
			//System.out.println(hexStr);
		}
		return sb.toString();
	}
<<<<<<< HEAD
	public static void enumASN1Object(Enumeration enumAsn1Object) throws IOException{
		
=======
	public static void enumASN1Object(Enumeration enumAsn1Object){
		/*
>>>>>>> 6ea783ac2bbc5a52429662a1068cdb9e3493ce2c
		while(enumAsn1Object.hasMoreElements()){
			Object asn1Object = enumAsn1Object.nextElement();
			if(asn1Object instanceof ASN1BitString){
				ASN1BitString asn1BitString = (ASN1BitString) asn1Object;
				String str = asn1BitString.getString();
				System.out.println(str);
			}else if(asn1Object instanceof ASN1EncodableVector
					||asn1Object instanceof ASN1Enumerated
					||asn1Object instanceof ASN1GeneralizedTime
					||asn1Object instanceof ASN1Generator
					||asn1Object instanceof ASN1InputStream
					||asn1Object instanceof ASN1Null){
				
			}else if(asn1Object instanceof ASN1ObjectIdentifier){
				ASN1ObjectIdentifier asn1ObjectIndentifier = (ASN1ObjectIdentifier) asn1Object;
				StringBuffer sb = new StringBuffer();
				sb.append(asn1ObjectIndentifier.getId());
				System.out.println(sb.toString());
				
			}else if(asn1Object instanceof ASN1String){
				ASN1String asn1String = (ASN1String) asn1Object;
				System.out.println(asn1String.getString());
			}else if(asn1Object instanceof ASN1Sequence){
				ASN1Sequence asn1Sequence = (ASN1Sequence) asn1Object;
				enumASN1Object(asn1Sequence.getObjects());
			}else if(asn1Object instanceof ASN1Set){
				ASN1Set asn1Set = (ASN1Set) asn1Object;
				enumASN1Object(asn1Set.getObjects());
			}else if(asn1Object instanceof DEROctetString){
				DEROctetString derOctetStr = (DEROctetString) asn1Object;
				System.out.println(derOctetStr.toString());
			}else if(asn1Object instanceof ASN1Integer){
				ASN1Integer asn1Int = (ASN1Integer) asn1Object;
				System.out.println(asn1Int.getValue());
			}else if(asn1Object instanceof ASN1Boolean){
				ASN1Boolean asn1Bool = (ASN1Boolean) asn1Object;
				System.out.println(asn1Bool.isTrue());
			}else{
				System.out.println(asn1Object.getClass());
			}
		}
<<<<<<< HEAD
		
=======
		*/
>>>>>>> 6ea783ac2bbc5a52429662a1068cdb9e3493ce2c
	}
}
