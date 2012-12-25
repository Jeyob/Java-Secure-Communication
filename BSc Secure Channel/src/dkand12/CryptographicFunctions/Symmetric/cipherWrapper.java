package dkand12.CryptographicFunctions.Symmetric;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;


public class cipherWrapper extends sCipher {

	private Cipher cipher = null;
	
	public cipherWrapper(String transformation) {
		try {
			this.ALGORITHM = transformation.split("/")[0];
			cipher = Cipher.getInstance(transformation);
		
		} catch(Exception e) {

			e.printStackTrace();
			System.exit(0);
		}
	}
	
	@Override
	public byte[] doFinal(byte[] plaintext) throws IllegalBlockSizeException, BadPaddingException {
		return cipher.doFinal(plaintext);
	}

	@Override
	public byte[] getParameters() {
		AlgorithmParameters algoparam = null;
		byte[] NULL = new byte[]{0}; 
			try {
				return (algoparam=cipher.getParameters())==null ? NULL:algoparam.getEncoded();
			} catch (IOException e) {
				e.printStackTrace();
			}
		
		return null;
	}

	@Override
	public void init(int opmode, byte[] key) {
		init(opmode,key,null);
	}

	@Override
	public void init(int opmode, byte[] key, byte[] parameters) {
		
		this.opmode = opmode;
		this.key = key;
		this.parameters = parameters;

		SecretKeySpec keyspec = new SecretKeySpec(key, ALGORITHM);
		
		try {
			if(parameters!=null){
				AlgorithmParameters ap = AlgorithmParameters.getInstance(this.ALGORITHM);
				ap.init(parameters);
				cipher.init(opmode, keyspec, ap);
			} else
				cipher.init(opmode, keyspec, SecureRandom.getInstance("SHA1PRNG"));
		
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(0);
		}
	}

	@Override
	public int getBlockSize() {
		return cipher.getBlockSize();
	}

	@Override
	public void fromDHinit(int opmode, byte[] DH_seed, String HashAlgorithm, byte[] params) {
		try{
			byte[] NULL = new byte[]{0};
			MessageDigest hash = MessageDigest.getInstance(HashAlgorithm); /* since the mutualsecret is only a keyseed we need to trim down the keysize using a hashfunction */
			byte[] mutualSecret = hash.digest(DH_seed);
			mutualSecret = Arrays.copyOf(mutualSecret, cipher.getBlockSize()); /* take blocksize bytes from digest as key */
			init(opmode, mutualSecret,Arrays.equals(params, NULL)?null:params);
		
		} catch(Exception e) {
			e.printStackTrace();
		}
	}

}
