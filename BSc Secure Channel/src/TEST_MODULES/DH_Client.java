package TEST_MODULES;

import java.io.IOException;
import java.net.Socket;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.util.Arrays;

import dkand12.Helpers.CipherIO;
import dkand12.Helpers.HelperMetods;

public class DH_Client implements Runnable {
	private KeyAgreement keyagreement = null;
	private int keysize = Integer.MIN_VALUE;
	private KeyPairGenerator keyPairGenerator = null;
	private KeyPair keypair = null;
	private Socket socket = null;
	private DHParameterSpec dhspec = null;
	private CipherIO stream = null;
	private byte[] mutualsecret = null;
	private X509EncodedKeySpec encodedKey = null;
	private KeyFactory keyfactory = null;
	
	
	private long start, stop, keyStart,keyStop;
	
	public DH_Client(int keysize, String host, int port) {
		this.keysize = keysize;
		try {
		
			socket = new Socket(host, port);
			stream = new CipherIO(socket);
		
		} catch(IOException e) {
			e.printStackTrace();
			System.exit(0);
		}
	}
	
	public void init() {
		try {
			
			keyfactory = KeyFactory.getInstance("DH");
			
			dhspec = generateParameters(keysize);
			keyPairGenerator = KeyPairGenerator.getInstance("DH");
			keyPairGenerator.initialize(dhspec);
			
			keyStart = System.currentTimeMillis();
			keypair = keyPairGenerator.generateKeyPair();
			keyStop = System.currentTimeMillis();
			
			System.out.print(keyStop-keyStart+",");
			
			keyagreement = KeyAgreement.getInstance("DH");
			keyagreement.init(keypair.getPrivate());
		
		}catch(Exception e) {
			e.printStackTrace();
		}
	}
	
	private DHParameterSpec generateParameters(int keysize) {
		DHParameterSpec spec = null;
		try {
			AlgorithmParameterGenerator apg = AlgorithmParameterGenerator
					.getInstance("DH");
			apg.init(keysize);
			AlgorithmParameters algParam = apg.generateParameters();
			spec = (DHParameterSpec)algParam
					.getParameterSpec(DHParameterSpec.class);
			

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidParameterSpecException e) {
			e.printStackTrace();
		}
		return spec; // something went wrong
	}
	
	public void run() {
	
	for(int ntimes = 0;ntimes<50;ntimes++) {
		start = System.currentTimeMillis();
		
		init();
		//first step publish the paramters and also the public key part
		stream.write2party(dhspec.getG().toByteArray(),dhspec.getP().toByteArray(),HelperMetods.int2byteAry(dhspec.getL()), keypair.getPublic().getEncoded()); 
		
		//wait for the 
		List<byte[]> received_data = stream.recieveFromParty();
		
		encodedKey = new X509EncodedKeySpec(received_data.get(0));
		
		try {
			//finish the exchange
			
			keyagreement.doPhase(keyfactory.generatePublic(encodedKey), true);
			mutualsecret = keyagreement.generateSecret();
			
			stop = System.currentTimeMillis();
		
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		System.out.println(stop-start+", "+Arrays.areEqual(received_data.get(1), mutualsecret));
	}
	}
	public static void main(String args[]) {
		DH_Client dhClient = new DH_Client(1024, "localhost", 8080);
		Thread t = new Thread(dhClient);
		t.start();
	}
}
