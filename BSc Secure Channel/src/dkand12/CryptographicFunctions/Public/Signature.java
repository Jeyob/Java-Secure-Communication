package dkand12.CryptographicFunctions.Public;

import java.security.PrivateKey;
import java.security.PublicKey;


public final class Signature {

	public static byte[] getSigned(byte[] msg, PrivateKey signKey, String signature_algorithm){
		try{
			
			java.security.Signature signer = java.security.Signature.getInstance(signature_algorithm);
			signer.initSign(signKey);
			signer.update(msg);
			
			return signer.sign();
			
		}catch(Exception e){
			e.printStackTrace();
		}
		
		return null;
		
	}
	
	public static boolean verifySignature(byte[] singedBytes, byte[] updateData, PublicKey verficationKey, String signature_algorithm) {
		
		try {
			
			java.security.Signature signer = java.security.Signature.getInstance(signature_algorithm);
			signer.initVerify(verficationKey);
			signer.update(updateData);
			
			return signer.verify(singedBytes);
		
		}catch(Exception e){
			e.printStackTrace();
		}
		
		return false;
		
	}
	
}