package TEST_MODULES;

import java.io.IOException;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;
import javax.crypto.KeyAgreement;
import dkand12.CryptographicFunctions.Symmetric.*;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import dkand12.Helpers.CipherIO;

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

	private long start, stop, keyStart, keyStop;

	public ECDH_Client(int keysize, String host, int port) {
		this.keysize = keysize;
		
		try {

			socket = new Socket(host, port);
			stream = new CipherIO(socket);

			keyfactory = KeyFactory.getInstance("ECDH");
//			keyPairGenerator = KeyPairGenerator.getInstance("ECDH", "BC");
//			
//			//NIST EC-Curve P-224"
//			org.bouncycastle.jce.spec.ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(EllipticCurveDiffieHellman.curveNames.get(new Integer(224)));
//			
//			keyPairGenerator.initialize(ecSpec, new SecureRandom());

		} catch (IOException | NoSuchAlgorithmException e) {
			e.printStackTrace();
			System.exit(0);
		}
	}

	public void generateKeyPair() {
		
		try {
			
			keyfactory = KeyFactory.getInstance("ECDH");

			keyPairGenerator = KeyPairGenerator.getInstance("ECDH", "BC");
		
			//NIST EC-Curve P-224"
			org.bouncycastle.jce.spec.ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(EllipticCurveDiffieHellman.curveNames.get(new Integer(224)));

			keyPairGenerator.initialize(ecSpec, new SecureRandom());

		int num = 10;

			/* Warm up */
			for (int wRound = 0; wRound < 200; wRound++) {
				keyPairGenerator.generateKeyPair(); 
			}

			/*
			 * Finding the right number of iterations such that we iterate for
			 * at least 2s
			 */
			for (;;) {
				
				long begin = System.currentTimeMillis();

				for (int i = 0; i < num; i++) {

					keypair = keyPairGenerator.generateKeyPair();
				}

				long end = System.currentTimeMillis();
				
				long time = end - begin;

				if (time >= 2000) {
					System.out.printf("Average keygen time: %.2f ms\n",
							(double) time / num);
					break;
				}

				num *= 2;
			}

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public void run() {

		generateKeyPair();
		System.exit(0);

		try {

			keyagreement = KeyAgreement.getInstance("ECDH");

			for (int ntimes = 0; ntimes < 50; ntimes++) {

				start = System.currentTimeMillis();

				keypair = keyPairGenerator.generateKeyPair();
				keyagreement.init(keypair.getPrivate());

				// System.out.print(keyStop-keyStart+",");
				// first step publish the paramters and also the public key part

				stream.write2party(keypair.getPublic().getEncoded());

				// wait for the
				List<byte[]> received_data = stream.recieveFromParty();

				encodedKey = new X509EncodedKeySpec(received_data.get(0));

				// finish the exchange

				keyagreement.doPhase(keyfactory.generatePublic(encodedKey),
						true);
				mutualsecret = keyagreement.generateSecret();

				stop = System.currentTimeMillis();

			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		// System.out.println(stop-start+","+Arrays.areEqual(received_data.get(1),
		// mutualsecret));
	}

	public static void main(String args[]) {
		Security.addProvider(new BouncyCastleProvider());
		ECDH_Client ECDHClient = new ECDH_Client(224, "localhost", 8080);
		Thread t = new Thread(ECDHClient);
		t.start();
	}
}