package dkand12.Login.controlstation;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

import com.sun.org.apache.xml.internal.security.utils.Base64;

import dkand12.Login.Login;
import dkand12.Server.HandshakeContext.LoginContext.sState;
import dkand12.CryptographicFunctions.Public.publicCrypto;
import dkand12.CryptographicFunctions.Public.publicCrypto.RSA;
import dkand12.Helpers.*;

public class cPhase_two implements sState{

	/**
	 * 
	 * in this phase we generate a secret nonce
	 * 
	 * Sends username & secret nonce to Mindstorm
	 * 
	 * @return		Base64 encoded (username, encrypted nonce)
	 * 
	 */
	
	public byte[] nextPhase(Login protocol) {
		try {
		System.out.println("**** PHASE two *****");
			
			publicCrypto.RSA encrypter = new publicCrypto.RSA("ECB", "PKCS1Padding");
			encrypter.initlize(Cipher.ENCRYPT_MODE, protocol.getKey());
			
			byte[] secureNonce = HelperMetods.generateSecureNonce();
			
			byte[] cipher = encrypter.encrypt(secureNonce, "UTF-8");
			
			byte[] username = protocol.getUsername().getBytes("UTF-8");
			
			byte[] usernameLen = HelperMetods.int2byteAry(username.length); // how long is the username
			
			byte[] first = HelperMetods.concatArrays(usernameLen, username);
			
			System.out.println("***** END PHASE two *****");
			protocol.write2socket(org.bouncycastle.util.encoders.Base64.encode(HelperMetods.concatArrays(first, cipher)));
			
		} catch(Exception e){
			e.printStackTrace();
		}
		
			return null;
		
	}
	

}
