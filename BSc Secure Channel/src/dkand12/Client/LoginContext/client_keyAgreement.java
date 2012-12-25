package dkand12.Client.LoginContext;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.asymmetric.ec.KeyAgreement;

import Communication.ChatClient;
import dkand12.CryptographicFunctions.Public.publicCrypto;
import dkand12.CryptographicFunctions.Public.publicCrypto.RSA;
import dkand12.CryptographicFunctions.Symmetric.DiffieHellman;
import dkand12.CryptographicFunctions.Symmetric.VermanDigest;
import dkand12.CryptographicFunctions.Symmetric.sCipher;
import dkand12.Helpers.CipherIO;
import dkand12.Helpers.Constants;
import dkand12.Helpers.HelperMetods;
import dkand12.Helpers.STATE;
import dkand12.KeyManager.CipherSetup;
import dkand12.Server.HandshakeContext.LoginContext.State;

public class client_keyAgreement extends StateContext {

	private ChatClient parent = null;
	private DiffieHellman keyagreement = null;
	private byte[] mutualSecret = null;
	
	
	public client_keyAgreement(ChatClient parent,CipherIO cipherIO, CipherSetup setup) {
		
		super(cipherIO, setup);
		
		this.parent = parent;
		try {
			keyagreement = DiffieHellman.getInstance(setup.getKeyExchangeAlgorithm());
		} catch(Exception e) {
			e.printStackTrace();
			setState(new ERROR_EXIT(e.getMessage(), true));
			System.exit(0);
		}
		
		setState(new PUBLISH_DH_SPEC()); //set init.state
	}
	
	
	/**
	 * 
	 * PUBLISH_DH_SPEC
	 * 
	 * Before entering the keyagreement phase, the DH parameters (i.e. primes p & g) must be known by both parties.
	 * 
	 * Here we simply create the necssecary parametes and broadcast them.
	 * 
	 * @author Jonas
	 *
	 */

	private final class PUBLISH_DH_SPEC implements State {

		@Override
		public boolean doPhase() {

			HelperMetods.print2console("Attempting to publish keyexchange parameters");
			
			write2Partie(keyagreement.getParameterStream()); /* send parameters  */
			
			HelperMetods.print2console("Keyexchange parameter spec published");
			
			setState(new DH_SPEC_PUBLISHED());
			
			return false;
		}

		@Override
		public STATE getSTATE() {
			return STATE.PUBLISH_DH_SPEC;
		}
	}
	
	/**
	 * 
	 * SENDING_PUBLICKEY_PART
	 * 
	 * This stage is reached when parameters has been broadcasted to the counter-partie.
	 * 
	 * Here we "create" the publickey part, and send it.
	 * 
	 * @author Jonas
	 *
	 */
	
	private final class DH_SPEC_PUBLISHED implements State {

		@Override
		public boolean doPhase() {
			
			HelperMetods.print2console("SENDING PUBLIC PART");
		
			System.out.print("(Keyagreement) publicpart: ");
			
			HelperMetods.printByteArray(keyagreement.getPublicKey().getEncoded());
			
			write2Partie(keyagreement.getPublicKey().getEncoded());

			setState(new AWATING_PUBLICPART_RESPONSE());
			
			return false;
		}

		@Override
		public STATE getSTATE() {
			return STATE.SENDING_PUBLICKEY_PART;
		}
	}
	
	/**
	 * 
	 * AWATING_PUBLICPART_RESPONSE
	 * 
	 * When: This stage is reached when the public part has been sent.
	 * 
	 * Does: Initially this state awaits the message coming from the server; the signature is verified. 
	 * 
	 * @author Jonas
	 *
	 */
	
	private final class AWATING_PUBLICPART_RESPONSE implements State {

		private List<byte[]> responseMsg = null;
		MessageDigest hash = null;
		byte[] mutualSecretSeed = null;
		SecretKey sessionSecret = null;
		sCipher eCipher = null;
		SecureRandom secretCounter = null;
		byte[] sessionkeybytes = null;
		
		@Override
		public boolean doPhase() {
			try{
				responseMsg = receivePartie(); /* server public part + signed hash with the public parts */
				
				byte[] MindstormPublicPart = responseMsg.get(0);
				byte[] MindstormDigestedPart = responseMsg.get(1);
				
				System.out.print("Received: ");
				HelperMetods.printByteArray(responseMsg.get(0));
				
				if(!MindstormPublicPart.equals(Constants.END_CONNECTION.getBytes())) { /* Check whether a end_request was sent */
				
					byte[] decrypted = publicCrypto.decrypter(MindstormDigestedPart, setup.getOtherPublicKey(), setup.getPublicKeyAlgorithm(), RSA.NO_MODE, setup.getPublicPaddingAlgorithm()); /* Decrypt/verifie the signed message */
					
					if(verify(MindstormPublicPart, keyagreement.getPublicKey().getEncoded(),decrypted)) { /* Performs some critical checks that ensures us the sender ID */
						
						HelperMetods.print2console("VERIFIED DIGEST!!");
						
						mutualSecretSeed = keyagreement.generateMutulSecret(keyagreement, MindstormPublicPart); /* Generate mutual secret */
						
						System.out.println("Mutualsecret:");
						
						HelperMetods.printByteArray(mutualSecretSeed);
						
						/****************** CREATE COUNTER ***********************************/
							secretCounter = SecureRandom.getInstance("SHA1PRNG"); /* counter used to prevent replay attacks */
						
							byte[] rndValue = new byte[16];
						
							secretCounter.nextBytes(rndValue); /* rndValue now contains the secretbytes forming the counter */
						
							setup.counter = new BigInteger(rndValue);
						
						/****************** Session key ********************************/
						
						if(setup.getSymmetricKeyAlgorithm().equalsIgnoreCase("verman")){
							
							sessionkeybytes = new byte[128]; //1024 bits
							SecureRandom s = SecureRandom.getInstance("SHA1PRNG");
							s.nextBytes(sessionkeybytes);
						
						} else { //if not verman
							KeyGenerator keygen = KeyGenerator.getInstance(setup.getSymmetricKeyAlgorithm());
							
							if(setup.getSymmetricKeySize()==Integer.MIN_VALUE)
								sessionkeybytes = keygen.generateKey().getEncoded();
							else { //specifed keysize
								keygen.init(setup.getSymmetricKeySize());
								sessionkeybytes = keygen.generateKey().getEncoded();
							}
						}
					
						setup.setSessionKey(sessionkeybytes); //set session key	
						
						eCipher = sCipher.getInstance(setup.getSymmetric_transformation()); 
						eCipher.fromDHinit(sCipher.ENCRYPT, mutualSecretSeed, setup.getHashAlgorithm(), null); //takes the DH seed, hashes it and takes the 16 first bytes 
						
						byte[] sessionKey_AND_Counter_Cipher = eCipher.doFinal(HelperMetods.foldMessage(setup.getSessionKey(), setup.counter.toByteArray())); /* Sessionkey + counter */
						
						HelperMetods.print2console("Trying to send client signed data");
						
						byte[] digest_data = createDigest(keyagreement.getPublicKey().getEncoded(),keyagreement.getEncodedExternalKey() ,setup.getRecipient_name().getBytes());
						byte[] ClientSignedData = publicCrypto.encrypter(digest_data, setup.getMyPrivateKey(), setup.getPublicKeyAlgorithm(), RSA.NO_MODE, setup.getPublicPaddingAlgorithm());
						
						write2Partie(ClientSignedData, eCipher.getParameters(), sessionKey_AND_Counter_Cipher); //signedresponse, IV or more, syncronization counter
						
						setState(new WATING_VERIFICATION_RESULT());
					}
					else
						setState(new ERROR_EXIT("public keypart not matching exptected", true));
				} else
					setState(new ERROR_EXIT("Unexpected exit", false));
				
			} catch(Exception e){
				e.printStackTrace();
				setState(new ERROR_EXIT("Exception cannot proceed", true));
			}
			
			return false; //continue!
		}
		
		@Override
		public STATE getSTATE() {
			return STATE.AWATING_PUBLICPART_RESPONSE;
		}
		
		private byte[] createDigest(byte[]...params) throws NoSuchAlgorithmException, IOException{
			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			
			for(byte[] arg:params)
				bos.write(arg);
			
			return MessageDigest.getInstance(setup.getHashAlgorithm()).digest(bos.toByteArray());
		}

		
		private boolean verify(byte[] recievedKey,byte[] ourkey, byte[] signed_data) throws SignatureException, InvalidKeyException, NoSuchAlgorithmException, IOException{
			
			HelperMetods.printByteArray(signed_data);
			
			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			MessageDigest digest = MessageDigest.getInstance(setup.getHashAlgorithm());
			
			bos.write(recievedKey);
			bos.write(ourkey);
			bos.write(setup.getUsername().getBytes());
						
			byte[] compareDigest = digest.digest(bos.toByteArray());
			
			return Arrays.equals(compareDigest, signed_data);
		
		}	
	}
	
	
	private final class WATING_VERIFICATION_RESULT implements State {

		@Override
		public boolean doPhase() {
			List<byte[]> respons = receivePartie(); //parameter + returninfo
			byte[] NULL = new byte[]{0};
			sCipher dCipher;
			
			try {
				
				
//				AlgorithmParameters params = AlgorithmParameters.getInstance(setup.getSymmetricKeyAlgorithm());
//		        params.init(respons.get(0));
//				
				//dCipher = sCipher.getInstance(setup.getSymmetric_transformation());
				//dCipher.init(sCipher.DECRYPT, setup.getSessionKey(), Arrays.equals(NULL,respons.get(0))?null:respons.get(0));
				
				//byte[] recovered = dCipher.doFinal(respons.get(1));
				
//				System.out.println(new String(recovered,"UTF-8"));

				if(Arrays.equals(respons.get(0), Constants.KEY_EXCHANGE_SUCCESS.getBytes())) {
					HelperMetods.print2console("DECIPHER MATCH");
					setState(new SUCCESS_EXIT());
					return false;
				}
				
			} catch (Exception e){
				e.printStackTrace();
			}
			
			setState(new ERROR_EXIT("Decrypted Message differed", false));
			
			return false;
		}

		@Override
		public STATE getSTATE() {
			return STATE.WATING_VERIFICATION_RESULT;
		}
		
	}
	
	
	
	private final class SUCCESS_EXIT implements State {

		
		
		@Override
		public boolean doPhase() {
			return true;
		}
		

		@Override
		public STATE getSTATE() {
			return STATE.SUCCESS_EXIT;
		}
		
	}
	
	
	private final class ERROR_EXIT implements State {
		
		private String Error_msg = null;
		private boolean send = true;
		
		public ERROR_EXIT(String msg, boolean send){
			Error_msg = msg;
			this.send = send;
			
		}
		
		@Override
		public boolean doPhase() {
			
			HelperMetods.print2console(Error_msg);
			
			if(send)
				write2Partie(Constants.END_CONNECTION.getBytes()); //tell server to end this connection attempt
			
			return true;
		}

		@Override
		public STATE getSTATE() {
			return STATE.ERROR_EXIT;
		}
		
		
		
	}
	
	
	
	
	

}
