package dkand12.CryptographicFunctions.Symmetric;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Base64Encoder;

import dkand12.Helpers.HelperMetods;

public final class VermanDigest extends sCipher {
//	private String ALGORITHM = "SHA-1"; // Are we using MD(2|4|5) or SHA-1 ?
	private MessageDigest digestFunc;
	private int IVSIZE = 16; //IVSIZE in bytes
	private static int RANDOMSEED_SIZE = 128;

	SecureRandom random = new SecureRandom();
	
	public VermanDigest(String transformation) {
//		this.ALGORITHM = digestAlgorithm;
		String[] params = null;
		
		String digestAlgorithm = (params=transformation.split("/")).length > 1 ? params[1] : "SHA-1";
		
		System.out.println("sent to verman: "+transformation);
		
		try{
			digestFunc = MessageDigest.getInstance(digestAlgorithm);
		}catch(Exception e){
			e.printStackTrace();
			System.exit(0);
		}
	}
	
	/**
	 * <p style="font-weight:bold;">Generates the Key stream, for which the message is later XOR'd with.<p>
	 * </br>
	 * The amount of key stream generated depends on the size of the message.
	 *  
	 * @param key	SecretKey
	 * @param nByte	the size of the message which is to be encrypted
	 * @param IV	the inital vector (used for the first block)
	 * @return		A linked list of bytes..
	 */
	
	private LinkedList<byte[]> generateKeyStream(byte[] keyBytes ,int nByte, byte[] IV) {
		
		int nRounds;
		LinkedList<byte[]> digestList = new LinkedList<byte[]>();
		
		nRounds = (digestFunc.getDigestLength() < nByte ? (int) nByte/digestFunc.getDigestLength() : 1); //calculates how many iterations we need (depends on which message digest we use)
		
		digestFunc.update(HelperMetods.concatArrays(keyBytes, IV)); //First block is initiated with the key and IV.
		
		byte[] b1 = digestFunc.digest(); //random bytes obtained by using a hash.
		digestList.add(b1);
		byte[] digest = b1;
		
		for(byte[] previous = b1; nRounds>0; nRounds--,previous = digest) {
			digest = digestFunc.digest(HelperMetods.concatArrays(keyBytes,previous));
			digestList.add(digest);
		}
		
		return digestList;
	}
	
	/**
	 * <b>ENCRYPT</b>
	 * 
	 * <p>Encrypts the message using a one-time pad (verman pad).
	 * 
	 * @param key The shared key only known to the valid parties
	 * @param msg	A byte[] containing the message to be encrypted; expecting a UTF-8 encoding.
	 * @return Ciphertext
	 * 
	 */
	
	// EDIT: changed all the occurences of IV to parameters
	
	public byte[] encrypt(byte[] key, byte[] plaintext) {
		byte[] result = null;
		try {
			
			//this.parameters = random.generateSeed(IVSIZE);
			
			LinkedList<byte[]> keyStream = generateKeyStream(key, plaintext.length, this.parameters); //generates enough key material. 
			
			result = new byte[plaintext.length];
			
			OUTERLOOP:
				for(int j = 0, blockPos = 0; j < plaintext.length; blockPos++){
					if(blockPos<keyStream.size()){
					for(byte b : keyStream.get(blockPos)) {
						result[j] = (byte) (plaintext[j] ^ b);
						if(!((++j)<plaintext.length))
							break OUTERLOOP;
					}
				}
			}
		} catch(Exception e) {
			e.printStackTrace();
		}
		
		return result;
	}
	
	public byte[] decrypt(byte[] key, byte[] IV, byte[] ciphertext){ 
		
		byte[] result = null;

			LinkedList<byte[]> keyStream = generateKeyStream(key, ciphertext.length, IV);
			result = new byte[ciphertext.length];
			OUTERLOOP:
				for(int j = 0, blockPos = 0; j < ciphertext.length; blockPos++){
					if(blockPos<keyStream.size()){
					for(byte b : keyStream.get(blockPos)) {
						result[j] = (byte) (ciphertext[j] ^ b); /* exclusiveOR with each bit */
						if(!((++j)<ciphertext.length))
							break OUTERLOOP;
					}
				}
			}
	return result;
	}
	
	private void dispose() {
		try {
			this.finalize();
			System.gc(); //invoke call to garbage collector so this object is cleaned up by the garbage collector
		} catch (Throwable e) {
			e.printStackTrace();
		}
	}

	@Override
	public void init(int opmode, byte[] key, byte[] parameters) {
		this.opmode = opmode;
		this.key = key;
		this.parameters = parameters == null ? random.generateSeed(IVSIZE) : parameters;
	}

	@Override
	public void init(int opmode, byte[] key) {
		init(opmode,key,null);
		
	}

	@Override
	public byte[] getParameters() {
		return this.parameters;
	}
	
	@Override
	public int getBlockSize() {
		return 0;
	}
	

	@Override
	public byte[] doFinal(byte[] plainORcipher) throws IllegalBlockSizeException,
			BadPaddingException {
	
		byte[] returnbytes = null;
		
		switch(opmode) {
			case sCipher.ENCRYPT:
				returnbytes = encrypt(key, plainORcipher);
				break;
				
			case sCipher.DECRYPT:
				returnbytes = decrypt(key, parameters, plainORcipher);
				break;
			default:
				System.err.println("Unrecognized operation mode");
			//	throw new UnrecoverableEntryException("unrecognized operation mode");
		}
		
		return returnbytes;
	}

	@Override
	public void fromDHinit(int opmode, byte[] DH_seed, String HashAlgorithm, byte[] params) {
		try{
			
			MessageDigest hash = MessageDigest.getInstance(HashAlgorithm); /* since the mutualsecret is only a keyseed we need to trim down the keysize using a hashfunction */
			
			byte[] digestedSecret = hash.digest(DH_seed);
			byte[] mutualSecret = Arrays.copyOf(digestedSecret, 16);

			System.out.println("Mutualsecret");
			HelperMetods.printByteArray(mutualSecret);
			
			init(opmode, mutualSecret, params);
		
		} catch(Exception e) {
			e.printStackTrace();
		}
	}
}
