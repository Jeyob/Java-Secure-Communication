package dkand12.Server.HandshakeContext.LoginContext;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;


import dkand12.CryptographicFunctions.Public.publicCrypto;
import dkand12.CryptographicFunctions.Public.publicCrypto.RSA;
import dkand12.Helpers.CipherIO;
import dkand12.Helpers.Constants;
import dkand12.Helpers.HelperMetods;
import dkand12.Helpers.STATE;
import dkand12.KeyManager.CipherSetup;
import org.bouncycastle.util.encoders.*;

public class S_Handshake {
	

	private CipherSetup setup = null;
	private State CurrentState = null;
	private Socket socket = null;
	private BufferedInputStream in = null;
	private BufferedOutputStream out = null;
	private ByteArrayOutputStream byteStream = null;
	private CipherIO cipherIO = null;
	
	
	public S_Handshake(CipherIO cipherIO, CipherSetup setup, STATE init_state) {
		
		byteStream = new ByteArrayOutputStream();
		this.setup = setup;
		this.cipherIO = cipherIO;

		switch (init_state) {	
			case FORCED_SHUTDOWN:
				CurrentState = new ERROR_EXIT("No connection slot free",false);
				break;
			case SLOT_PROVIDED:
				CurrentState = new AWAITING_CLIENT_HELLO();
				break;
		}
	}

	public boolean doPhase() {
		return CurrentState.doPhase();
	}

	public STATE getState() {
		return CurrentState.getSTATE();
	}
	
	private void setState(State newState){
		CurrentState = newState;
	}

		

/** 
 * AWATING_CLIENT_HELLO
 * 
 * <p>This state of the protocol handles the wating and responding to the: client hello + supported ciphersuites.</p>
 * 
 * 
 * @author Jonas
 *
 */


private final class AWAITING_CLIENT_HELLO implements State {

	ByteArrayOutputStream byteStream = null;
	List<byte[]> messages = null;
	private final int CLIENTHELLO = 0;
	private final int CIPHERSPEC = 1;
	
	
	public AWAITING_CLIENT_HELLO() {
		byteStream = new ByteArrayOutputStream();
	}

	public STATE getSTATE() {
		return STATE.AWATING_CLIENT_HELLO;
	}
	
	
	public boolean doPhase() {
		
		byte[] encodedMsg, nbytes = new byte[4], decodedMessage = null, encodedCipherSpec = null, decodedCipherSpec = null;
		String str = null;
		int bytes2read, bytes;

		try {
		
			messages = cipherIO.recieveFromParty();
			
			str = new String(messages.get(CLIENTHELLO));

			if (Arrays.equals(messages.get(CLIENTHELLO), Constants.DEFAULT_CLIENT_HELLO.getBytes())) { /* check that client hello was received, if so, then continue reading cipherspecs */ 

				str = new String(messages.get(1));

				String suite = chooseCipher(str.split(","));
				
				if(suite==null)
					throw new Exception("No matching cipher suites found");
				
				setup.fromCipherSuite(suite);
				
				byte[] Choice = suite.getBytes(); 
				byte[] serverHello = Constants.DEFAULT_SERVER_HELLO.getBytes();
				
				cipherIO.write2party(serverHello,Choice);
				
				setState(new CLIENT_HELLO_RESPONDED());

			} else
				setState(new ERROR_EXIT("Undefined response received at this time",true));

		}catch(Exception e){
			e.printStackTrace();
			setState(new ERROR_EXIT(e.toString(),true));
		}
		
		return false;
	}
	
	private String chooseCipher(String[] suites) {
		Iterator<String> it = setup.getSupportedCiphers();
		
		for(String s = it.next(); it.hasNext(); s=it.next()){
			for(String suite:suites){
				if(s.equalsIgnoreCase(suite))
					return s;
			}
		}
		
		return null; //if we come here then a matching suite could not be found
	}

}

/**
 * Client_HELLO_RESPONDED
 * 
 * This state is reached when the clientHello has been received and answered
 * 
 * Here we now wait for the Client to username followed with a challange.
 * If user is indeed a registered user of the system then the challage is responded along with a serverchallange to the client 
 * 
 * @author Jonas
 *
 */


private final class CLIENT_HELLO_RESPONDED implements State {

	List<byte[]> messages = null;
	private final int USERNAME = 0;
	private final int CHALLANGE = 1;
	
	
	@Override
	public boolean doPhase() {
		
		messages = cipherIO.recieveFromParty(); /* username + challange */
		
		if(!messages.get(0).equals(Constants.END_CONNECTION.getBytes())){
			byte[] username = messages.get(USERNAME);
			byte[] challange = messages.get(CHALLANGE);
	
			try {
				
				if(setup.getKeyStore().containsAlias(new String(username))){
					/* username exist  */
					setup.setRecipient_name(new String(username)); /* set recipient in enviroment */
					setup.setOtherPublicKey(setup.getKeyStore().getCertificate(new String(username)).getPublicKey()); //set public key
					
					byte[] decrypted_Client_Challange = publicCrypto.decrypter(challange, setup.getMyPrivateKey(), setup.getPublicKeyAlgorithm(), RSA.NO_MODE, setup.getPublicPaddingAlgorithm());
					
					byte[] server_challange = HelperMetods.generateSecureNonce();
					
					byte[] encryptedServer_challange = publicCrypto.encrypter(server_challange, setup.getOtherPublicKey(), setup.getPublicKeyAlgorithm(), RSA.NO_MODE, setup.getPublicPaddingAlgorithm());
					
					cipherIO.write2party(decrypted_Client_Challange, encryptedServer_challange); /* send serverChallange. */
					
					setState(new CLIENT_CHALLENGE_RESPONDED(server_challange));
					
				}else 
					setState(new ERROR_EXIT("User not present in keystore",true));
				
			} catch(Exception e){
				e.printStackTrace();
			}
		}else 
			setState(new ERROR_EXIT("End connection requested by client..", false));
			
		return false;
	}

	@Override
	public STATE getSTATE() {
		return STATE.CLIENT_HELLO_RESPONDED;
	}
	
}


/**
 * CLIENT_CHALLANGE_RESPONDED
 * 
 * State is reached here when the client challange has been recieved and answered along with a Server challange that
 * should be honored with a respons from the client.
 * 
 * Here we wait for the client response and verifies that the correct challenge is returned.
 * 
 * @author Jonas
 *
 */

private final class CLIENT_CHALLENGE_RESPONDED implements State {

	byte[] server_challenge = null;
	
	public CLIENT_CHALLENGE_RESPONDED(byte[] serverchallenge){
		
		server_challenge = serverchallenge;
		
	}
	
	@Override
	public boolean doPhase() {
		byte[] client_response = cipherIO.recieveFromParty().get(0); /* only the challene is sent */
		System.out.println(setup);
		if(Arrays.equals(server_challenge, client_response)) {
			cipherIO.write2party(Constants.LOGIN_GRANTED.getBytes()); /* send access granted */ 
			setState(new SUCCESS_EXIT());
		}
		else
			setState(new ERROR_EXIT("Received nonce did not match servers", true));
		
		return false;
	}

	@Override
	public STATE getSTATE() {
		return STATE.CLIENT_CHALLENGE_RESPONDED;
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

	private String errorMsg = null;
	private boolean send = false;
	
	public ERROR_EXIT(String errorMessage, boolean send) {
		errorMsg = errorMessage; /*sends end connection message along with errorMessage */
	}

	public STATE getSTATE() {
		return STATE.ERROR_EXIT;
	}

	public boolean doPhase() { /* Send message back to client */
		
		HelperMetods.print2console(errorMsg);
		
		if(send)
			cipherIO.write2party(Constants.DEFAULT_DENY_RESPONSE.getBytes());

		return true; /* true, we do not continue */
	}

}

}
