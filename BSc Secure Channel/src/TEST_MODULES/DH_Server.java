package TEST_MODULES;

import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;

import dkand12.Helpers.CipherIO;
import dkand12.Helpers.HelperMetods;

public class DH_Server implements Runnable{
	
	private ServerSocket serversocket = null;
	private Socket connectedClient = null; 
	private CipherIO stream = null;
	private KeyPair keypair = null;
	private DHParameterSpec dhspec = null;
	private X509EncodedKeySpec keyspec = null;
	private KeyPairGenerator keypairgenerator = null;
	private KeyAgreement keyagreement = null;
	private KeyFactory keyfactory = null;
	
	public DH_Server(int port) {
		try {
			serversocket = new ServerSocket(port);
			
		}catch(Exception e) {
			e.printStackTrace();
			System.exit(0);
		}
	}
	
	private void init(BigInteger G, BigInteger P, int L, PublicKey pkey) {
		
		try {
			
		keyagreement = KeyAgreement.getInstance("DH");
		dhspec = new DHParameterSpec(P, G, L);
		keypairgenerator = KeyPairGenerator.getInstance("DH");
		keypairgenerator.initialize(dhspec);
	
		keypair = keypairgenerator.generateKeyPair();
		
		keyagreement.init(keypair.getPrivate());
		keyagreement.doPhase(pkey, true);
		
		}catch(Exception e) {
			e.printStackTrace();
			System.exit(0);
		}
	}
	
	public void run() {
		try {
			connectedClient = serversocket.accept();
			stream = new CipherIO(connectedClient);
		} catch (IOException e) {
			e.printStackTrace();
			System.exit(0);
		}
		
		for(int ntimes = 0;ntimes<50;ntimes++) {
			
		List<byte[]> specs = stream.recieveFromParty();
		
		keyspec = new X509EncodedKeySpec(specs.get(3));
		
		try {
		keyfactory = KeyFactory.getInstance("DH");
		
		
		init(new BigInteger(specs.get(0)), new BigInteger(specs.get(1)), HelperMetods.byteAry2int(specs.get(2)),keyfactory.generatePublic(keyspec));
		
		}catch(Exception e) {
			e.printStackTrace();
			System.exit(0);
		}
		
		stream.write2party(keypair.getPublic().getEncoded(),keyagreement.generateSecret());
		}		
	}
	
	public static void main(String args[]) {
		DH_Server server = new DH_Server(8080);
		Thread t = new Thread(server);
		t.start();
	}

}
