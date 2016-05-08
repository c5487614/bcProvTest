package cn.org.hbca.bc;

import java.util.Enumeration;

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
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;

public class Util {

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
	public static void enumASN1Object(Enumeration enumAsn1Object){
		while(enumAsn1Object.hasMoreElements()){
			Object asn1Object = enumAsn1Object.nextElement();
			if(asn1Object instanceof ASN1BitString){
				ASN1BitString asn1BitString = (ASN1BitString) asn1Object;
				String str = asn1BitString.getString();
				System.out.println(str);
			}else if(asn1Object instanceof ASN1Boolean
					||asn1Object instanceof ASN1Integer
					||asn1Object instanceof ASN1EncodableVector
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
			}
		}
	}
}
