package Communication;

import java.net.*;
import java.security.KeyStore;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicInteger;
import java.io.*;


import dkand12.Helpers.CipherIO;
import dkand12.Helpers.HelperMetods;
import dkand12.Helpers.STATE;
import dkand12.KeyManager.CipherSetup;
import dkand12.Server.HandshakeContext.LoginContext.S_Handshake;
import dkand12.Server.HandshakeContext.LoginContext.server_keyAgreement;

public class ClientHandler extends ChatServer implements Runnable {
	
	private Socket socket;
	private S_Handshake handshake = null;
	private server_keyAgreement keyAgreement = null;
	private Properties properties = null;
	private KeyStore keystore = null; 
	private CipherSetup setup = null;
	private AtomicInteger nConnected = null;
	private STATE slotStatus = null;
	private CipherIO cipherIO = null;
	
	private boolean last_state = false; /* used to flag if the last state of the object is encountered */

	
	public ClientHandler(Socket socket, STATE status, AtomicInteger nConnected) {
		this.socket = socket;
		properties = new Properties();
		slotStatus = status;
		this.nConnected = nConnected;
		
		try{
			
			keystore = KeyStore.getInstance("JKS");
			properties.load(new FileInputStream("Mindstorm/Mindstorm.properties"));
			keystore.load(new FileInputStream("Mindstorms"), "password".toCharArray()); //TODO: perhaps provide a better password 
			
			setup = new CipherSetup("mindstorm", properties, keystore);
			cipherIO = new CipherIO(socket);
			
		}catch(FileNotFoundException e){
		
			e.printStackTrace();
			System.err.println("Mindstorm properties file: not found!");
			System.exit(0);
		
		}catch(IOException e){
			System.err.println("Problem with in-/output stream");
		}catch(Exception e){
			e.printStackTrace();
		}
		
		
	switch(status) {
		case NO_SLOTS_AVAILABLE: //connection not possible at this time
			handshake = new S_Handshake(cipherIO, setup, STATE.FORCED_SHUTDOWN);
			break;
		case SLOT_PROVIDED: //no one is currently connected
			nConnected.getAndIncrement();
			handshake = new S_Handshake(cipherIO, setup, STATE.SLOT_PROVIDED);
			break;
		default:
				throw new IllegalArgumentException("unrecognized state");		
		}		
	}

	
	public void run() {
	
		do { /* Protocol start & end here */ 
			
			last_state = handshake.doPhase();
			
		} while(!last_state); /* loop while still more work to do */
	
		/* we come here after either success or failure
		  if success then we want to spawn a new thread with two states (reading and writing) */
		
		switch(handshake.getState()) {
			case ERROR_EXIT: 
				System.out.println("Exiting application");
				if(slotStatus!=STATE.NO_SLOTS_AVAILABLE)
					nConnected.decrementAndGet();
				break;
			case SUCCESS_EXIT: //now a session key has been 
				System.out.println("Continue to keyAgreement");
				
				keyAgreement = new server_keyAgreement(cipherIO, setup); 
				
				last_state = false;
				do {
					last_state = keyAgreement.doNext(); 
					
				}while(!last_state);
				
				switch(keyAgreement.getSTATE()){
					case ERROR_EXIT:
						HelperMetods.print2console("Exiting application");
						nConnected.decrementAndGet();
						break;
					case SUCCESS_EXIT:
						HelperMetods.print2console("Key exchange succeeded!");
						Thread t = new Thread(new ReceiveFromServer(socket, cipherIO,setup));
						Thread tt = new Thread(new UDP_Client_Writer(999, socket.getInetAddress(), 2048, 10000));
						t.start();
						tt.start();
						break;
				}
				
				break;
			default: 
				System.out.println("Unrecognized state");
				break;
			
		}
	}
	
}
