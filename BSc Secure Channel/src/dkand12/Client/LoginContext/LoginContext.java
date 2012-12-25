package dkand12.Client.LoginContext;

import java.util.Arrays;
import java.util.List;
import javax.crypto.Cipher;
import Communication.ChatClient;
import dkand12.Helpers.CipherIO;
import dkand12.Helpers.Constants;
import dkand12.Helpers.HelperMetods;
import dkand12.KeyManager.CipherSetup;
import dkand12.CryptographicFunctions.Public.publicCrypto;
import dkand12.Server.HandshakeContext.LoginContext.*;
import dkand12.Helpers.STATE;

public class LoginContext {
	
	private CipherSetup setup = null;
	private ChatClient parent = null;
	private State CurrentState = null;
	private CipherIO cipherIO = null;
	
	public LoginContext(ChatClient parent,CipherIO cipherIO, CipherSetup setup){
		
		this.parent = parent;
		this.setup = setup;
		this.cipherIO = cipherIO;

		SetState(new Connection_Slot_Received());
	}

	public boolean doNext(){
		return CurrentState.doPhase();
	}
	
	public void SetState(State s){
		CurrentState = s;
	}
	
	public STATE getCurrentState(){
		return CurrentState.getSTATE();
	}
	
	
		
	/****************************************************************************************************************************/
	
	/**
	 * <b>Connection_Slot_Received</b>
	 * 
	 *  <p>The context reaches this state when a connection attempt to the server was successful.
	 * 	<p> In this class the phase of writing (clienthello) and reciving (serverhello) is done.
	 * 
	 *
	 */
	
	private final class Connection_Slot_Received implements State {
		
		@Override
		public boolean doPhase() {
			
			System.out.println("\nSTATE: CONNECTION_SLOT_RECEIVED\n");
			
			List<byte[]> serverMessages = null;
			byte[] supportedCiphers = null;
			byte[] clientHello = null;
			
			try {
				
				supportedCiphers = setup.getProperties().getProperty("supported_ciphers").getBytes("UTF-8");
				clientHello = Constants.DEFAULT_CLIENT_HELLO.getBytes("UTF-8");
				
				System.out.println("\n**** ATTEMPTING TO SEND CLIENTHELO ****\n");
				
				cipherIO.write2party(clientHello, supportedCiphers); //send clientHello
				
				System.out.println("\n**** SENDING DONE.. ****\n");
				System.out.println("\n**** Wating for Server Helo ****\n");
				
				serverMessages = cipherIO.recieveFromParty(); //get server respons
				
				System.out.println("\n**** SERVER RESPONSE RECEVIED ****\n");
		
				if(serverMessages.isEmpty() || serverMessages.get(0).equals(Constants.UNSUPPORTED_CIPHERSUIT_ERROR.getBytes()))
					SetState(new ERROR_EXIT("ServerHello respons failure", true));
				else if(serverMessages.get(0).equals(Constants.END_CONNECTION))
					SetState(new ERROR_EXIT("Server requesting end connection",false));
				else {
					setup.fromCipherSuite(new String(serverMessages.get(1))); //choosen suite by server
					SetState(new Cipher_Spec_Agreed());
				}
				
			}catch(Exception e){
				e.printStackTrace();
				SetState(new ERROR_EXIT("encoding exception", true));
			}
			
			return false; //last state not reached yet: Continue!
		}

		@Override
		public STATE getSTATE() {
			return STATE.Connection_Slot_Received;
		}
		
}
	
	
	/****************************************************************************************************************************/
	
	/**
	 * <b>Cipher_Spec_Agreed<b>
	 * 
	 * <p>The context reaches this state after client and server has agreed on a ciphersetup.
	 * 
	 * <p> This class takes care of sending the serverChallange (username+encryptedNonce)
	 * 
	 * @author Jonas
	 *
	 */
	
	private final class Cipher_Spec_Agreed implements State {

		@Override
		public boolean doPhase() {
			try{
				
				byte[] ServerChallenge = HelperMetods.generateSecureNonce();
				byte[] username = setup.getUsername().getBytes("UTF-8");	
			
				cipherIO.write2party(username,publicCrypto.encrypter(ServerChallenge, setup.getOtherPublicKey(), setup.getPublicKeyAlgorithm(), "NONE", setup.getPublicPaddingAlgorithm()));
				
				SetState(new ClientChallange_Sent(ServerChallenge)); //set new state
				
			}catch(Exception e){
				
				e.printStackTrace();
				
				SetState(new ERROR_EXIT(e.toString(),true));
			}
			
			return false;
		}

		@Override
		public STATE getSTATE() {
			return STATE.Cipher_Spec_Agreed;
		}
	}
	
	
	/****************************************************************************************************************************/
	
		/**
		 * <b>ClientChallange_Sent<b>
		 * 
		 * <p>The context reaches this state after client has sent the challange to server.
		 * 
		 * <p>This class takes care of receiving the serverChallange (decrypted clientnonce + encryptedServerNonce)
		 * 
		 * @author Jonas
		 *
		 */
	
	private final class ClientChallange_Sent implements State {

		byte[] expectedNonce = null;
		List<byte[]> servermessage = null;
		Cipher decipher = null;
		
		public ClientChallange_Sent(byte[] secretNonce) {
			
			try {
				
				expectedNonce = secretNonce;			
				decipher = Cipher.getInstance(setup.getPublicKeyAlgorithm());
				decipher.init(Cipher.DECRYPT_MODE, setup.getMyPrivateKey());
				
			}catch(Exception e){
				e.printStackTrace();
			}
		}
			@Override
			public boolean doPhase() {
				
				servermessage = cipherIO.recieveFromParty(); //wait for server to reply
				
				if(Arrays.equals(expectedNonce, servermessage.get(0))) { //assuming that the decrypted nonce is placed first in the list
					/* if we get here then server identity is confirmed */
					try {
				
						byte[] decryptedNonce = publicCrypto.decrypter(servermessage.get(1), setup.getMyPrivateKey(), setup.getPublicKeyAlgorithm(), "NONE", setup.getPublicPaddingAlgorithm());
					
						cipherIO.write2party(decryptedNonce); //reply server

						SetState(new ServerChallange_Responded());
					
					}catch(Exception e){
						e.printStackTrace();
					}
					
				} else
					SetState(new ERROR_EXIT("Decrypted nonce from server did not match excpeted",true));
				return false;
			}

			@Override
			public STATE getSTATE() {
				return STATE.ClientChallange_Sent;
			}
	}
	
	/****************************************************************************************************************************/	
	
	/**
	 * <b> ServerChallange_Responded
	 * 
	 * <p> The context only reaches this state after client has responded to ServerChallenge
	 * 
	 * <p> This class takes care of waiting for the Granted/Denied response from the server.
	 * 
	 * @author Jonas
	 *
	 */
	
	private final class ServerChallange_Responded implements State {

		@Override
		public boolean doPhase() {
			
			List<byte[]> finalMessage = cipherIO.recieveFromParty();
			
			if(Arrays.equals(finalMessage.get(0), Constants.LOGIN_GRANTED.getBytes())) {
				SetState(new SUCCESS_EXIT());
				HelperMetods.print2console("ACCESS GRANTED");
			}
			else {
				SetState(new ERROR_EXIT("Access denied", true));
				HelperMetods.print2console("ACCESS DENIED");
			}
			return false;
		}
		
		@Override
		public STATE getSTATE() {
			return STATE.ServerChallange_Responded;
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
				cipherIO.write2party(Constants.END_CONNECTION.getBytes()); //tell server to end this connection attempt
			
			return true;
		}

		@Override
		public STATE getSTATE() {
			return STATE.ERROR_EXIT;
		}
	}
}


