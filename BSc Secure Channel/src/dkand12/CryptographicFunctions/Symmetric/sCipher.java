package dkand12.CryptographicFunctions.Symmetric;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Provider;
import java.util.HashMap;
import java.util.Hashtable;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

import dkand12.KeyManager.CipherSetup;

import Communication.interfaces.CryptoObject;

public abstract class sCipher {

	public static final int ENCRYPT = 1;
	public static final int DECRYPT = 2;

	protected int opmode;
	protected byte[] key;
	protected byte[] parameters;
	protected byte[] IV;
	protected String ALGORITHM;

	public abstract void init(int opmode, byte[] key, byte[] parameters);

	public abstract void init(int opmode, byte[] key);
	
	public abstract void fromDHinit(int opmode, byte[] DH_seed, String HashAlgorithm, byte[] params);
	
	public byte[] getIV() { /* if available */
		return IV;
	}
	
	public abstract byte[] getParameters();/* should be overridden in subclass */

	public abstract byte[] doFinal(byte[] plaintext) throws IllegalBlockSizeException, BadPaddingException ; /* depending on init either encrypt or decrypt */

	
	public abstract int getBlockSize();
	
	public static sCipher getInstance(String transformation) {
		
		String algorithm = transformation.split("/")[0];
		
		if (algorithm.equalsIgnoreCase("Verman"))
			return new VermanDigest(transformation);
		else /* algorithms that fall into this category can be used with java provided Cipher class */
			return new cipherWrapper(transformation);
	}

}
