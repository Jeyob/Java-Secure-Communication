package dkand12.Server.HandshakeContext.LoginContext;

import dkand12.Helpers.STATE;

public interface State {

	/**
	 * doPhase
	 * 
	 * Executes current state
	 * @return true if final state has been reached, otherwise false
	 */
	public boolean doPhase();
	
	public STATE getSTATE();

}
