package TEST_MODULES;

import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import dkand12.Helpers.CipherIO;
import dkand12.Helpers.HelperMetods;

public class ECDH_Server implements Runnable {
	private ServerSocket serversocket = null;
	private Socket connectedClient = null; 
	private CipherIO stream = null;
	private KeyPair keypair = null;
	private ECParameterSpec ec_spec = null;
	private X509EncodedKeySpec keyspec = null;
	private KeyPairGenerator keypairgenerator = null;
	private KeyAgreement keyagreement = null;
	private KeyFactory keyfactory = null;
	
	public ECDH_Server(int port) {
		try {
			serversocket = new ServerSocket(port);
			
		}catch(Exception e) {
			e.printStackTrace();
			System.exit(0);
		}
	}
	
	private void init(ECPublicKey pkey) {
		
		try {
			
		keyagreement = KeyAgreement.getInstance("ECDH");
		ec_spec = pkey.getParams();
		keypairgenerator = KeyPairGenerator.getInstance("ECDH");
		keypairgenerator.initialize(ec_spec);
	
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
		
		keyspec = new X509EncodedKeySpec(specs.get(0));
		
		try {
		keyfactory = KeyFactory.getInstance("ECDH");
		
		
		init((ECPublicKey)keyfactory.generatePublic(keyspec));
		
		}catch(Exception e) {
			e.printStackTrace();
			System.exit(0);
		}
		
		stream.write2party(keypair.getPublic().getEncoded(),keyagreement.generateSecret());
		}		
	}
	
	public static void main(String args[]) {
		Security.addProvider(new BouncyCastleProvider());
		ECDH_Server server = new ECDH_Server(8080);
		Thread t = new Thread(server);
		t.start();
	}
}
