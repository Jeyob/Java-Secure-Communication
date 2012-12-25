package Communication;

import java.io.IOException;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.NoSuchPaddingException;
import dkand12.Client.LoginContext.LoginContext;
import dkand12.Client.LoginContext.client_keyAgreement;
import dkand12.CryptographicFunctions.Symmetric.DH;
import dkand12.CryptographicFunctions.Symmetric.EllipticCurveDiffieHellman;
import dkand12.Helpers.CipherIO;
import dkand12.Helpers.HelperMetods;
import dkand12.Helpers.STATE;
import dkand12.KeyManager.CipherSetup;

public class ChatClient implements Runnable {
	
	private Socket connect = null;
	private LoginContext loginContext = null;
	private client_keyAgreement keyAgreement= null;
	private CipherSetup cipherSetup = null;
	private CipherIO cipherIO = null;
	private final String RECEIVER = "mindstorm";
	
	public ChatClient(String username, KeyStore userstore,java.util.Properties clientProperties,String serverAddress, int port) throws InterruptedException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IOException {
		int nTries = 0;
		boolean isSuccess = false;
		
		System.out.printf("Attempting connection to %s on port: %d\n\n", serverAddress, port);
		
		do {

			try {
				connect = new Socket(serverAddress, port); // make connection
				
				System.out.println("Connection successfully established");
				
				isSuccess = true;
			
			} catch (IOException e) {

				if (nTries >= 5) {
					System.out
							.println("More than 5 re-connection attempts without success....Shutting down.. ");
					System.exit(0);
				}

				System.out.println("Could not connect to host, retrying connection..Attempt: "
								+ nTries++);
				System.out.println();

				Thread.sleep(2000*nTries); /* some delay between reconnection */
				
			}

		} while (!isSuccess);
		
		cipherSetup = new CipherSetup(username, clientProperties, userstore); //create environmentSetup
		
		cipherSetup.setRecipient_name(RECEIVER);
		
		cipherIO = new CipherIO(connect);
	}

	@Override
	public void run() {
		
		
		HelperMetods.print2console("Initiating handshake with Server..");
		
		loginContext = new LoginContext(this, cipherIO, cipherSetup);  
		
		HelperMetods.print2console(String.format("Subphase: trying to authenticate to %s..",RECEIVER));
		
		boolean isDone = false;
		do {
			isDone = loginContext.doNext(); 
		} while(!isDone);
		
		
		if(loginContext.getCurrentState() == STATE.ERROR_EXIT) {
			System.out.println("Handshake failed");
			System.exit(0);
		}
		
		HelperMetods.print2console("Subphase(Login): authentication successful");
		
		HelperMetods.print2console(String.format("Subphase(Keyagreement): Initiating Keyexchange phase with %s",RECEIVER));
		
		keyAgreement = new client_keyAgreement(this, cipherIO, cipherSetup);
		
		isDone = false;
		do {
			
			isDone = keyAgreement.doNext();
			
		}while(!isDone);
		
		if(keyAgreement.getSTATE() == STATE.ERROR_EXIT){
			HelperMetods.print2console("Key exchange failed");
			System.exit(0);
		}
		
		HelperMetods.print2console("Key Exchange successful");
		
		/* If we come here then client and server has established a secret key */
		
		Thread t = new Thread(new Write2Server(connect, cipherSetup, cipherIO));
		Thread tt = new Thread(new UDP_SERVER(999,cipherSetup));
		t.start();
		tt.start();
	
	}

}
