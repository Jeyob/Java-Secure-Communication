package dkand12.Client;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import javax.xml.crypto.AlgorithmMethod;


public class CustomSecureSocket extends Socket  {
	
	private String encryptionAlgorithm;
	
	public CustomSecureSocket(InetAddress adress, int port) throws IOException {
		this(adress.getHostName(),port,false,"RSA");
	}
	
	public CustomSecureSocket(String host, int port) throws IOException {
		this(host, port,false,"RSA");
	}
	
	public CustomSecureSocket(String host, int port, boolean stream) throws IOException{
		this(host,port,false,"RSA");
	}
	
	public CustomSecureSocket(String host, int port, boolean stream, String encryptAlgortihm) throws IOException{
		super(host,port,stream);
		this.encryptionAlgorithm = encryptAlgortihm;
	}
}
