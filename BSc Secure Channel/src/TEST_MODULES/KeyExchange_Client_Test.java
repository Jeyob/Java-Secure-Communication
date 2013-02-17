package TEST_MODULES;

import java.io.IOException;
import java.net.Socket;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;
import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.JDKKeyPairGenerator.DH;
import org.bouncycastle.util.Arrays;

import dkand12.Helpers.CipherIO;
import dkand12.Helpers.HelperMetods;

public class KeyExchange_Client_Test implements Runnable {

	private KeyAgreement keyagreement = null;
	private int keysize = Integer.MIN_VALUE;
	private KeyPair keypair = null;
	private Socket socket = null;
	private DHParameterSpec dhspec = null;
	private CipherIO stream = null;
	private byte[] mutualsecret = null;
	private X509EncodedKeySpec encodedKey = null;
	private KeyFactory keyfactory = null;

	// keypair generators
	private DH DHkeypairgen = null;
	private KeyPairGenerator ECkeypairgen = null;

	// constants
	private final String ECDH192 = "P-192";
	private final String ECDH224 = "P-224";
	private final int DH2056 = 2056;
	private final int DH2783 = 2783;
	private static final String[] names = new String[] { "ECDH192", "ECDH224",
			"DH2056", "DH2783" };

	// choose crypto: iter=0 (ECDH192), iter=1 (ECDH224), iter=2 (DH2056) and iter=3 (DH2783)
	public static final int iter = 3;
	
	public KeyExchange_Client_Test(int keysize, String host, int port) {

		try {

			this.keysize = keysize;

			socket = new Socket(host, port);
			stream = new CipherIO(socket);

		} catch (IOException e) {

			e.printStackTrace();

			System.exit(0);
		}
	}

	
	//Warmup 
	public void warmUp(int iter, String Agreement) throws Exception {
		
		KeyAgreement keyAgreement1 = KeyAgreement.getInstance( Agreement );
 		KeyAgreement keyAgreement2 = KeyAgreement.getInstance( Agreement );
		KeyPair pair1, pair2;
 		
		if (iter > 1) {
			/* Warm up rounds */
			for (int wRun = 0; wRun < 200; wRun++) {

				pair1 = DHkeypairgen.generateKeyPair();
				pair2 = DHkeypairgen.generateKeyPair();
				
				keyAgreement1.init(pair1.getPrivate());
				keyAgreement2.init(pair2.getPrivate());
				
				keyAgreement1.doPhase(pair2.getPublic(), true);
				keyAgreement2.doPhase(pair1.getPublic(), true);
				
				keyAgreement1.generateSecret();
				keyAgreement2.generateSecret();
				
				//Warm up of the channel
				stream.write2party(pair1.getPublic().getEncoded());
				
				stream.recieveFromParty();
				
			}
		} else {

			for (int wRun = 0; wRun < 200; wRun++) {

				pair1 = ECkeypairgen.generateKeyPair();
				pair2 = ECkeypairgen.generateKeyPair();
				
				keyAgreement1.init(pair1.getPrivate());
				keyAgreement2.init(pair2.getPrivate());
				
				keyAgreement1.doPhase(pair2.getPublic(), true);
				keyAgreement2.doPhase(pair1.getPublic(), true);
				
				keyAgreement1.generateSecret();
				keyAgreement2.generateSecret();
				
				stream.write2party(pair1.getPublic().getEncoded());
				stream.recieveFromParty();

			}

		}

	}
	
	//not used
	private DHParameterSpec generateParameters(int keysize) {
		DHParameterSpec spec = null;
		try {
			AlgorithmParameterGenerator apg = AlgorithmParameterGenerator
					.getInstance("DH");
			apg.init(keysize);
			AlgorithmParameters algParam = apg.generateParameters();
			spec = (DHParameterSpec) algParam
					.getParameterSpec(DHParameterSpec.class);

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidParameterSpecException e) {
			e.printStackTrace();
		}
		return spec; // something went wrong
	}

	public void run() {

		String Agreement;

 
		try {

			/* DH */
			DHkeypairgen = new DH();

			/* ECDH */
			ECkeypairgen = KeyPairGenerator.getInstance("ECDH");
			
			
				keyfactory = KeyFactory
						.getInstance((Agreement = iter > 1 ? "DH" : "ECDH"));

				keyagreement = KeyAgreement.getInstance( Agreement );

				if (iter > 1) { // DH (2056 | 2783)

					DHkeypairgen.initialize(iter == 2 ? DH2056 : DH2783,
							new SecureRandom());

				} else { // ECDH (192 | 224)

					ECGenParameterSpec ecspec = new ECGenParameterSpec(
							iter == 0 ? ECDH192 : ECDH224);

					ECkeypairgen.initialize(ecspec, new SecureRandom());

				}

				if(iter < 2)
					warmUp(0, "ECDH"); /* warm up key pair generation */
				else
					warmUp(2, "DH");
				

				long start = System.currentTimeMillis();

				for (int ntimes = 0; ntimes < 50; ntimes++) {

					// generate keypair
					if (iter > 1)
						keypair = DHkeypairgen.generateKeyPair();
					else
						keypair = ECkeypairgen.generateKeyPair();

					// initlize keyagreement
					keyagreement.init(keypair.getPrivate());

					// publish public key part
					stream.write2party(keypair.getPublic().getEncoded());

					// wait for counter public part
					List<byte[]> received_data = stream.recieveFromParty();
					
					encodedKey = new X509EncodedKeySpec(received_data.get(0));

					// finish the exchange
					keyagreement.doPhase(keyfactory.generatePublic(encodedKey),
							true);
					
					mutualsecret = keyagreement.generateSecret();

					boolean areEqual = Arrays.areEqual(received_data.get(1),
							mutualsecret);

					if (!areEqual) {

						throw new Exception();
					}
				}

				long stop = System.currentTimeMillis();

				long time = stop - start;

				System.out.printf("%s Average key exchange time: %.2f ms\n",
						names[iter], (double) time / 50);

		} catch (Exception e) {
			e.printStackTrace();
			System.exit(0);
		}
	}

	public static void main(String args[]) {

		Security.addProvider(new BouncyCastleProvider());

		KeyExchange_Client_Test dhClient = new KeyExchange_Client_Test(1024,
				"localhost", 8080);

		Thread t = new Thread(dhClient);

		t.start();
	}
}
