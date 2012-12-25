package dkand12.CryptographicFunctions.Symmetric;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class DES extends symmetricCrypto {


	private Cipher eCipher = null, dCipher = null;
	private SecretKey secretKey;
	private byte[] iv;

	public DES(SecretKey key)
			throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, InvalidAlgorithmParameterException {
			eCipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
			dCipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
			secretKey = key;
			eCipher.init(Cipher.ENCRYPT_MODE, secretKey);
			
			
	}

	public byte[] encrypt(String msg) {

		try {

			byte[] msgBytes = msg.getBytes("UTF-8");
			return eCipher.doFinal(msgBytes); // The first 16 bytes of the
												// ciphertext is the IV

		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}

		return null; // if encryption was unsuccessful
	}

	public String decrypt(byte[] msg) throws UnsupportedEncodingException {
		byte[] decryptedMessage = null;
		
		try {
			dCipher.init(Cipher.DECRYPT_MODE, secretKey,new IvParameterSpec(eCipher.getIV()));
			decryptedMessage = dCipher.doFinal(msg);
		}  catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}

		return new String(decryptedMessage, "UTF-8");
	}

	public void updateKey(SecretKey key) {
		if (key != null)
			this.secretKey = key;
		else
			throw new IllegalArgumentException(
					"UpdateKey: Null parmeter not allowed");
	}
}
