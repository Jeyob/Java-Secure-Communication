package dkand12.CryptographicFunctions.Symmetric;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import Communication.interfaces.CryptoObject;

import dkand12.Helpers.HelperMetods;
import dkand12.Helpers.returnCode;

public class AES extends sCipher implements CryptoObject {
	/* MACRO */
	public final int IVSIZE = 16; //Size if init.vector
	
	private Cipher eCipher = null, dCipher = null;
	private SecretKey secretKey;
	private SecureRandom random;
	
	public AES(SecretKey key) throws NoSuchAlgorithmException,NoSuchPaddingException,InvalidKeyException, InvalidAlgorithmParameterException {
			this(key,"CBC", "PKCS5Padding");
	}

	public AES(SecretKey key, String ModeOfOperation) throws NoSuchAlgorithmException,NoSuchPaddingException,InvalidKeyException, InvalidAlgorithmParameterException {
		this(key,ModeOfOperation,"PKCS5Padding");
	}
	
	public AES(SecretKey key, String ModeOfOperation, String padding) throws NoSuchAlgorithmException,NoSuchPaddingException,InvalidKeyException, InvalidAlgorithmParameterException  {
		if(ModeOfOperation.matches("[A-Za-z]+")){

			eCipher = Cipher.getInstance(String.format("AES/%s/PKCS5Padding", ModeOfOperation));
			dCipher = Cipher.getInstance(String.format("AES/%s/PKCS5Padding", ModeOfOperation));
			
			secretKey = key;
			random = SecureRandom.getInstance("SHA1PRNG");
			random.setSeed(System.currentTimeMillis());
			
			eCipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(new byte[IVSIZE]),random);
		}
		else
			throw new IllegalArgumentException("AES: Invalid input format");
		}
		
	public byte[] encrypt(byte[] plaintext) {

		try {
//			byte[] msgBytes = msg.getBytes("UTF-8");
			return HelperMetods.concatArrays(eCipher.getIV(),eCipher.doFinal(plaintext)); // The first 16 bytes of the ciphertext is the IV
			
		}  catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		
		return null; //if encryption was unsuccessful
	}
	
	public byte[] decrypt(byte[] msg) {
		
		byte[] initIV = new byte[IVSIZE] , decryptedMessage = null, message = new byte[msg.length - IVSIZE];
		System.arraycopy(msg, 0, initIV, 0, IVSIZE); // read the IV 
		/* removes the 16 bytes belonging to the IV */
		System.arraycopy(msg, IVSIZE, message,0, msg.length - IVSIZE); 
		
		try {
		
			dCipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(initIV));
			
			decryptedMessage = dCipher.doFinal(message);
		
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		
//		return new String(decryptedMessage,"UTF-8");
	return decryptedMessage;
	}

	public void updateKey(SecretKey key) {
		if (key != null)
			this.secretKey = key;
		else
			throw new IllegalArgumentException(
					"UpdateKey: Null parmeter not allowed");
	}

	@Override
	public void init(int opmode, SecretKey key, byte[] parameters) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public byte[] doFinal(byte[] plaintext) {
		// TODO Auto-generated method stub
		return null;
	}

}
