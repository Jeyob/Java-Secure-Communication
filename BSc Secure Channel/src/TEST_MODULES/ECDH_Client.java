package TEST_MODULES;

import java.io.IOException;
import java.net.Socket;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;

import dkand12.Helpers.CipherIO;
import dkand12.Helpers.HelperMetods;

public class ECDH_Client implements Runnable {

		private KeyAgreement keyagreement = null;
		private int keysize = Integer.MIN_VALUE;
		private KeyPairGenerator keyPairGenerator = null;
		private KeyPair keypair = null;
		private Socket socket = null;
		private CipherIO stream = null;
		private byte[] mutualsecret = null;
		private X509EncodedKeySpec encodedKey = null;
		private KeyFactory keyfactory = null;
		
		
		private long start, stop, keyStart,keyStop;
		
		public ECDH_Client(int keysize, String host, int port) {
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
				
				keyfactory = KeyFactory.getInstance("ECDH");
	
				keyPairGenerator = KeyPairGenerator.getInstance("ECDH");
				keyPairGenerator.initialize(keysize);
				
				keyStart = System.currentTimeMillis();
				keypair = keyPairGenerator.generateKeyPair();
				keyStop = System.currentTimeMillis();
				
				System.out.print(keyStop-keyStart+",");
				
				keyagreement = KeyAgreement.getInstance("ECDH");
				keyagreement.init(keypair.getPrivate());
			
			}catch(Exception e) {
				e.printStackTrace();
			}
		}
		

		public void run() {
		
		for(int ntimes = 0;ntimes<50;ntimes++) {
			start = System.currentTimeMillis();
			init();
			//first step publish the paramters and also the public key part
			stream.write2party(keypair.getPublic().getEncoded()); 
			
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
			
			System.out.println(stop-start+","+Arrays.areEqual(received_data.get(1), mutualsecret));
		 }
		}
		public static void main(String args[]) {
			Security.addProvider(new BouncyCastleProvider());
			ECDH_Client ECDHClient = new ECDH_Client(224, "localhost", 8080);
			Thread t = new Thread(ECDHClient);
			t.start();
		}
	}