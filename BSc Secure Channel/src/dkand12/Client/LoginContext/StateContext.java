package dkand12.Client.LoginContext;

import java.util.List;

import dkand12.Helpers.CipherIO;
import dkand12.Helpers.STATE;
import dkand12.KeyManager.CipherSetup;
import dkand12.Server.HandshakeContext.LoginContext.State;

public abstract class StateContext {

	private CipherIO cipherIO = null;
	protected CipherSetup setup = null;
	private State current_state = null;

	protected StateContext(CipherIO cipherIO, CipherSetup setup){
		
		this.cipherIO = cipherIO;
		this.setup = setup;
		
	}
	
	public void setState(State newState) {
		current_state = newState;
	}
	
	public STATE getSTATE(){
		return current_state.getSTATE();
	}
	
	public boolean doNext(){
		return current_state.doPhase();
	}
	
	public void write2Partie(byte[]...msg){
		cipherIO.write2party(msg);
	}
	
	public List<byte[]> receivePartie(){
		return cipherIO.recieveFromParty();
	}
	
}
