package TEST_MODULES;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.asymmetric.ec.KeyAgreement;
import org.bouncycastle.jce.provider.asymmetric.ec.KeyFactory.ECDH;
import org.bouncycastle.jce.provider.asymmetric.ec.Signature;

import com.sun.org.apache.bcel.internal.generic.ALOAD;

import dkand12.CryptographicFunctions.Symmetric.sCipher;
import dkand12.Helpers.HelperMetods;

import sun.security.ec.ECDHKeyAgreement;

public class kryptoTest {

	public static void main(String args[]) throws NoSuchProviderException, SignatureException, InvalidParameterSpecException{
		Security.addProvider(new BouncyCastleProvider());
		
		byte[] key = new byte[128];
		try {
			SecureRandom.getInstance("SHA1PRNG").nextBytes(key);
			sCipher s = sCipher.getInstance("Verman");
			sCipher ss = sCipher.getInstance("Verman");
			
			s.fromDHinit(sCipher.ENCRYPT, key, "SHA1",null);
			
			byte[] ciphertext =	s.doFinal("jonas".getBytes());

			System.out.println(s.getParameters() == null);
			
			ss.fromDHinit(sCipher.DECRYPT, key, "SHA1",s.getParameters());
			
			HelperMetods.printByteArray(ciphertext);
			
			byte[] plaintext = ss.doFinal(ciphertext);
			
			System.out.println(new String(plaintext));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	
		
		
		
//		try {
			
//			AlgorithmParameterGenerator algoGen = AlgorithmParameterGenerator.getInstance("DH");
//			algoGen.init(1024);
//
//			AlgorithmParameters params = algoGen.generateParameters();
//			
//			DHParameterSpec dhspec = (DHParameterSpec)params.getParameterSpec(DHParameterSpec.class);
//			
//			System.out.println("Bit len :"+dhspec.getP().bitLength());
//			
//			java.security.Signature signer = java.security.Signature.getInstance("SHA256withRSAandMGF1");
//			java.security.Signature signer2 = java.security.Signature.getInstance("SHA1WithRSA");
//			
//			byte[] sbytes = new SecureRandom().generateSeed(200);
//			byte[] bytes = MessageDigest.getInstance("SHA-224").digest(sbytes);
//			
//			System.out.println("bytes size: "+bytes.length);
//			
//			KeyPairGenerator factory = KeyPairGenerator.getInstance("RSA");
//			KeyPair pair = factory.generateKeyPair();
//			
//			
//			
//			
//			Cipher c = Cipher.getInstance("RSA/NONE/OAEPWithMD5AndMGF1Padding","BC");
//			Cipher cc = Cipher.getInstance("RSA","BC");
//			
//			javax.crypto.KeyAgreement agreement = javax.crypto.KeyAgreement.getInstance("ECDH", "BC");
//			
//			
//			ECDH ecdhfac = new ECDH();
//			org.bouncycastle.jce.provider.asymmetric.ec.KeyPairGenerator.ECDH ecdh = (org.bouncycastle.jce.provider.asymmetric.ec.KeyPairGenerator.ECDH) org.bouncycastle.jce.provider.asymmetric.ec.KeyPairGenerator.ECDH.getInstance("ECDH");
//			
//			ecdh.initialize(384);
//			
//			
//			
//			KeyPair pari = ecdh.generateKeyPair();
//			
//			System.out.println(pari.getPublic());
//			
//			//System.out.println(agreement.generateSecret());
//			
//			c.init(Cipher.ENCRYPT_MODE, pair.getPrivate());
//			cc.init(Cipher.ENCRYPT_MODE, pair.getPrivate());
//			
////			System.out.println(pair.getPrivate());
////			System.out.println(pair.getPrivate());
//			
//			byte[] cout = c.doFinal(bytes);
//			
//			signer.initVerify(pair.getPublic());
//			System.out.println(signer.verify(cout));
//			
//			System.out.println("cout size: "+cout.length);
//			
//			byte[] ccout = cc.doFinal(bytes);
//			
//			for(byte b:cout){
//				System.out.print(b);
//			}
//			System.out.println();
//			
//			for(byte bb: ccout) {
//				System.out.print(bb);
//			}
//			System.out.println();
//			
//		} catch (NoSuchAlgorithmException 
//				| NoSuchPaddingException e) {
//			e.printStackTrace();
//		} catch (InvalidKeyException e) {
//			e.printStackTrace();
//		} catch (IllegalBlockSizeException e) {
//			e.printStackTrace();
//		} catch (BadPaddingException e) {
//			e.printStackTrace();
//		}
		
		
}
	
}
