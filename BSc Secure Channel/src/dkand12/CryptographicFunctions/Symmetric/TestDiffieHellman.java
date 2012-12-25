package dkand12.CryptographicFunctions.Symmetric;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Arrays;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import dkand12.CryptographicFunctions.Symmetric.EllipticCurveDiffieHellman.ECCSTRENGTH;
import dkand12.Helpers.HelperMetods;

public class TestDiffieHellman {
	
	public static void main(String[] args) throws NoSuchAlgorithmException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException{
		Security.addProvider(new BouncyCastleProvider());
		
//	DH keyagre = new DH();
//		EllipticCurveDiffieHellman DHBOB = new EllipticCurveDiffieHellman(224);
//	EllipticCurveDiffieHellman DHALICE = new EllipticCurveDiffieHellman(((org.bouncycastle.jce.interfaces.ECPublicKey)DHBOB.getPublicKey()).getParameters());
//	byte[] bob = DHBOB.generateMutulSecret(DHBOB,DHALICE.getPublicKey().getEncoded(),"ECDH");
//	byte[] alice = DHALICE.generateMutulSecret(DHALICE,DHBOB.getPublicKey().getEncoded(),"ECDH");
//	
//if(Arrays.equals(bob, alice) && bob != null && alice != null)
//		System.out.println("MATCH");
//	else
//		System.out.println("NO MATCH");
		
		KeyGenerator gen = KeyGenerator.getInstance("DES");
		gen.init(56);
		
		SecretKey key = gen.generateKey();
		
		sCipher s = sCipher.getInstance("Verman/SHA-1");
		sCipher ss = sCipher.getInstance("Verman/SHA-1");
		s.init(sCipher.ENCRYPT, key.getEncoded());
		byte[] ciphertext = s.doFinal("Visual basic".getBytes());
		//List<byte[]> unfolded = HelperMetods.unfoldMessage(ciphertext);
		ss.init(sCipher.DECRYPT, key.getEncoded(), s.getParameters());
		byte[] deciphered = ss.doFinal(ciphertext);
		System.out.println(new String(deciphered));
		
//		
//		SecretKey key2 = gen.generateKey();
//		VermanDigest v = new VermanDigest("SHA-1");
//		byte[] name = new byte[]{106,111};
//		byte[] array = v.encrypt(key,"MIRAN DAGS O GÖRA DIN PROLOG!!".getBytes("UTF-8"));
//		
//		System.out.println();
//		System.out.println("***** BEGIN CIPHERTEXT *******");
//		for(byte b: array){
//			System.out.print(b);
//		}
//		System.out.println();
//
//		System.out.println("****** END CIPHERTEXT ********");
//		
//		byte[] ary2 = v.decrypt(key, array);
//		
//		
//		System.out.println();
//		System.out.println(new String(ary2,"UTF-8"));
	
	
	}

	}
