package dkand12.Client;

import java.net.InetAddress;

public interface IClient {
	
	void makeHandShake(); // agree on a session-key

	boolean connectTo(InetAddress address, int port); // connect to specified address and port  
	
	boolean connectTo(String address, int port);
	
	void send(byte[] msg); // send the message

	void updateSessionKey(); // update the session-key; preventing ciphertext attacks.
	
	boolean dissConnect(); //dissconnects current connection
	
	
}
