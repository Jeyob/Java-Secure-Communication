package dkand12.Login.controlstation;

import java.io.IOException;

import org.bouncycastle.util.encoders.Base64;

import dkand12.CryptographicFunctions.Public.publicCrypto;
import dkand12.Helpers.Constants;
import dkand12.Login.Login;
import dkand12.Server.HandshakeContext.LoginContext.sState;


/*
 * sends a connection request to server. If access is granted then proceed to
 * phase 2 if not then exit
 */
public class cPhase_one implements sState { // initiator

	public byte[] nextPhase(Login protocol) {
		byte[] encodedMsg = null;
		byte[] respons = null;
		byte[] decodedMsg = null;

		try {
			encodedMsg = new byte[] { 'H', 'E', 'L', 'O' };
			protocol.write2socket(encodedMsg); // Send message
			System.out.println("WATING FOR RESPONS");
			respons = protocol.readSocket(); // respons from MINDSTORM
			System.out.println("RESPONS RECIEVED");
			decodedMsg = Base64.decode(respons);

			String str = new String(decodedMsg, "UTF-8");
System.out.println(str);
			if (str.equals(Constants.DEFAULT_AVAILABILITY_RESPONS))
				protocol.setState(new cPhase_two());
			else {
				System.err.println("Already a user connected to Mindstorm");
				System.exit(0);
			}
		} catch (IOException e) {
			e.printStackTrace();
		}

		return null;
	}
}