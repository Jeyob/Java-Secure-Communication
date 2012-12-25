package dkand12.CryptographicFunctions.Public;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.management.loading.PrivateClassLoader;
import org.bouncycastle.jce.provider.asymmetric.ec.Signature.ecCVCDSA;
import org.bouncycastle.util.encoders.Base64;

import dkand12.Helpers.Constants;
import dkand12.Helpers.HelperMetods;
import dkand12.Helpers.HelperMetods.RSA_Mode;

public abstract class publicCrypto {

	private Cipher eCipher, dCipher;
	protected final String ALGORITHM;
	private SecureRandom sRandom;
	private PrivateKey prKey = null; 
	private PublicKey puKey = null;
	//public final int IVSIZE = 16; //Size if init.vector
	private String mode;
	
	protected publicCrypto(String algorithm) throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException { //mode=NONE
		this(algorithm,"NONE","NoPadding");
	}
	
	/**
	 * Creates an instance of given publicEncryption type. The padding type is implicitly set to <b>PKCS5Padding
	 * @param algorithm
	 * @param mode
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws NoSuchProviderException
	 * @see	<a href = "http://docs.oracle.com/javase/1.4.2/docs/guide/security/jce/JCERefGuide.html#AppA">http://docs.oracle.com/javase/1.4.2/docs/guide/security/jce/JCERefGuide.html#AppA</a>
	 */
	protected publicCrypto(String algorithm, String mode) throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException{
		this(algorithm,mode,"PKCS5Padding");
	}
	
	protected publicCrypto(String algorithm, String mode, String padding) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException{
		this.ALGORITHM = algorithm;
		this.mode = mode;
		eCipher = Cipher.getInstance(algorithm+"/"+mode+"/"+padding,"BC");
		dCipher = Cipher.getInstance(algorithm+"/"+mode+"/"+padding,"BC");
		sRandom = SecureRandom.getInstance("SHA1PRNG");
		sRandom.setSeed(System.currentTimeMillis());

	}
	
	
	public void initlize(int keySize) throws InvalidKeyException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		
		generateKeyPair(keySize);
		
		if(HelperMetods.IVModes.contains(mode)) /* Does the current mode require IV?  */
			eCipher.init(Cipher.ENCRYPT_MODE, puKey,new IvParameterSpec(new byte[Constants.DEFAULT_IVSIZE]),sRandom);
		else
			eCipher.init(Cipher.ENCRYPT_MODE, puKey);
	}
	
	public void initlize(PublicKey key) throws InvalidKeyException, InvalidAlgorithmParameterException{
		if(HelperMetods.IVModes.contains(mode)) /* Does the current mode require IV?  */
			eCipher.init(Cipher.ENCRYPT_MODE, key,new IvParameterSpec(new byte[Constants.DEFAULT_IVSIZE]),sRandom);
		else
			eCipher.init(Cipher.ENCRYPT_MODE, key);
	}
	
	

	protected void generateKeyPair(int keySize) throws NoSuchAlgorithmException{ // generate the pubic key pair
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
		keyGen.initialize(keySize);
		KeyPair keyPair = keyGen.generateKeyPair();
		prKey = keyPair.getPrivate();
		puKey = keyPair.getPublic();
	}
	
	/**
	 * <b>encrypt</b>
	 * 
	 * <p>Encrypts the message and returns a byte array containing the ciphertext.</p>
	 * <p>Note: If the currently used mode requires an IV, this will consist of the IVSIZE bytes.</p>
	 * @param msg		The message to be encrypted
	 * @param charset	 
	 * @return	byte[] - Ciphertext
	 * @throws InvalidAlgorithmParameterException 
	 * @throws InvalidKeyException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchProviderException 
	 * @throws NoSuchAlgorithmException 
	 * @throws UnsupportedEncodingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	
	public static byte[] encrypter(byte[] plaintext,Key key, String algorithm,String chainmode,String padding) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
		boolean isIVmode = false;
		SecureRandom sRandom = null;
		Cipher eCipher = Cipher.getInstance(algorithm+"/"+chainmode+"/"+padding,"BC");
		
		if((isIVmode=HelperMetods.IVModes.contains(chainmode))) { /* Does the current mode require IV?  */
			
			sRandom = SecureRandom.getInstance("SHA1PRNG");
			sRandom.setSeed(System.currentTimeMillis());
			eCipher.init(Cipher.ENCRYPT_MODE, key,new IvParameterSpec(new byte[Constants.DEFAULT_IVSIZE]),sRandom);
		
		} else
			eCipher.init(Cipher.ENCRYPT_MODE, key);
		
		if(isIVmode)
			return HelperMetods.concatArrays(eCipher.getIV(), eCipher.doFinal(plaintext));
		else
			return eCipher.doFinal(plaintext);
	}
	
	public static byte[] decrypter(byte[] msg, Key key,String algorithm,String chainmode,String padding) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		
		Cipher dCipher = Cipher.getInstance(algorithm+"/"+chainmode+"/"+padding,"BC");
		
		byte[] decryptedMessage = null, initIV = null, message = null;
		
		if(HelperMetods.IVModes.contains(chainmode)){
			initIV = new byte[Constants.DEFAULT_IVSIZE];
			message = new byte[msg.length - Constants.DEFAULT_IVSIZE];
			
			/* Retrieves the IV from the beginning of the message  */
			System.arraycopy(msg, 0, initIV, 0, Constants.DEFAULT_IVSIZE); // read the IV 
			
			/* removes the 16 bytes belonging to the IV */
			System.arraycopy(msg, Constants.DEFAULT_IVSIZE, message,0, msg.length - Constants.DEFAULT_IVSIZE); 
			
			/* init cipher and decrypt */
			dCipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(initIV));
			decryptedMessage = dCipher.doFinal(message);
		
		} else { /* Without the need for a IV */
			
			dCipher.init(Cipher.DECRYPT_MODE, key);
			decryptedMessage = dCipher.doFinal(msg);
		
		}			
		
		return (decryptedMessage);
	}
	
	public byte[] encrypt(byte[] msg, String charset) throws UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException{
		byte[] result = null;

		if(HelperMetods.IVModes.contains(mode))
			result = HelperMetods.concatArrays(eCipher.getIV(), eCipher.doFinal(msg));
		else
			result = eCipher.doFinal(msg);
		
		return result;
		
	}
	
	public byte[] decrypt(byte[] encodedCipherMsg) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException{
		return decrypt(encodedCipherMsg, prKey);
	}
	
	public byte[] decrypt(byte[] encodedCipherMsg, Key key) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
		byte[] msg = Base64.decode(encodedCipherMsg);
		byte[] decryptedMessage = null;
		if(HelperMetods.IVModes.contains(mode)){
		byte[] initIV = new byte[Constants.DEFAULT_IVSIZE] , message = new byte[msg.length - Constants.DEFAULT_IVSIZE];
		System.arraycopy(msg, 0, initIV, 0, Constants.DEFAULT_IVSIZE); // read the IV 
		/* removes the 16 bytes belonging to the IV */
		System.arraycopy(msg, Constants.DEFAULT_IVSIZE, message,0, msg.length - Constants.DEFAULT_IVSIZE); 
		
			dCipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(initIV));
			decryptedMessage = dCipher.doFinal(message);
		}else{
			dCipher.init(Cipher.DECRYPT_MODE, key);
			decryptedMessage = dCipher.doFinal(msg);
		}			
		
		return (decryptedMessage);
	}

	public static class RSA extends publicCrypto {
		public static final String NO_PADDING = "NoPadding";
		public static final String NO_MODE = "NONE";
		
		public RSA() throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException {
			super("RSA");
		}
		public RSA(String mode) throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException {
			super("RSA", mode);
		}
		public RSA(String mode, String padding) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException{
			super("RSA",mode,padding);
		}
	
	}
		
	
	

	
	
}
