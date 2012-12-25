package dkand12.Login.Mindstorm;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import dkand12.Helpers.HelperMetods;
import dkand12.Login.Login;
import dkand12.Server.LoginContext.State;
import dkand12.CryptographicFunctions.Public.*;
import dkand12.CryptographicFunctions.Public.publicCrypto.RSA;

public class mPhase_two implements State {

	/**
	 * For phase 2 Mindstorm expects the username and encrypted key to be passed
	 * along
	 * 
	 * Mindstorm then:
	 * 
	 * 1. consultes the user registry for matching username and public key 2.
	 * decrypts the encrypted nonce 3. creates a secure nonce and encrypts this
	 * with the found public key
	 * 
	 */
	private String username = null;
	private byte[] encryptedNonce = null;
	private KeyStore keystore = null;
	private X509Certificate certificate = null;
	private RSA decipher = null, encipher = null;
	
	
	public mPhase_two(String username, byte[] encryptedNonce) {
		this.username = username;
		this.encryptedNonce = encryptedNonce;
		try {
			decipher = new RSA("CBC","PKC1PADDING");
			encipher= new RSA("CBC","PKC1PADDING");
			
			keystore = KeyStore.getInstance("JKS");
			keystore.load(new FileInputStream(
					"C:\\Program Files\\Java\\jre6\\bin\\keystore.jks"),
					"password".toCharArray());
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(0);
		}
	}

	@Override
	public byte[] nextPhase(Login protocol) {
		
		/******************** part 2  - decrypt secretnonce and create secret nonce ****************************/
		
		try {
			
			if(keystore.containsAlias(username)){ //does keystore contain username
				 certificate = (X509Certificate)keystore.getKey(username, "password".toCharArray());
				 byte[] decryptedNonce = decipher.decrypt(encryptedNonce, certificate.getPublicKey());
				 
				 byte[] mindstormSecret = HelperMetods.generateSecureNonce();
				 byte[] mindstorm_encryptedNonce = encipher.
				 
				 
		}
		
			
			
			
		}catch(KeyStoreException e){
			System.err.println("alias not found");
		} catch (UnrecoverableKeyException e) {
			System.err.println("Key could not be recovered");
		} catch (NoSuchAlgorithmException e) {
			System.err.println("unrecoginized keyalgorithm");
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
	}

}
