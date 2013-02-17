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
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.JDKKeyPairGenerator.DH;

import dkand12.Helpers.CipherIO;
import dkand12.Helpers.HelperMetods;

public class KeyExchange_Server_Test implements Runnable {

	private ServerSocket serversocket = null;
	private Socket connectedClient = null;
	private CipherIO stream = null;
	private KeyPair keypair = null;
	private DHParameterSpec dhspec = null;
	private ECParameterSpec ecspec = null;
	private X509EncodedKeySpec keyspec = null;
	private KeyPairGenerator keypairgenerator = null;
	private DH DHkeyGen = null;
	private KeyAgreement keyagreement = null;
	private KeyFactory keyfactory = null;

	public KeyExchange_Server_Test(int port) {
		try {
			serversocket = new ServerSocket(port);

		} catch (Exception e) {
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

		} catch (Exception e) {
			e.printStackTrace();
			System.exit(0);
		}
	}

	private void init(PublicKey pkey, String type, int iter) {

		try {

			keyagreement = KeyAgreement.getInstance(type);
			
			

			if (iter > 1) {
				DHkeyGen = new DH();
				dhspec = ((DHPublicKey) pkey).getParams();
				DHkeyGen.initialize(dhspec);
				keypair = DHkeyGen.generateKeyPair();
			} else {
				keypairgenerator = KeyPairGenerator.getInstance(type);
				ecspec = ((ECPublicKey) pkey).getParams();
				keypairgenerator.initialize(ecspec);
				keypair = keypairgenerator.generateKeyPair();
			}


			keyagreement.init(keypair.getPrivate());

			keyagreement.doPhase(pkey, true);

		} catch (Exception e) {

			e.printStackTrace();

			System.exit(0);
		}
	}

	public void warmUp(CipherIO io) {
		try {
			KeyFactory factory = KeyFactory.getInstance("DH");

				
				for (int iter = 0; iter < 200; ++iter) {

					List<byte[]> data = io.recieveFromParty();

					keyspec = new X509EncodedKeySpec(data.get(0));

					factory.generatePublic(keyspec);

					io.write2party("warmUp".getBytes());

				}

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	public void run() {

		String Agreement;

		try {

			connectedClient = serversocket.accept();

			stream = new CipherIO(connectedClient);
		
			warmUp(stream);

		} catch (IOException e) {

			e.printStackTrace();

			System.exit(0);
		}


			try {

				keyfactory = KeyFactory
						.getInstance((Agreement = KeyExchange_Client_Test.iter > 1 ? "DH" : "ECDH"));

				for (int ntimes = 0; ntimes < 50; ntimes++) {

					List<byte[]> specs = stream.recieveFromParty();

					keyspec = new X509EncodedKeySpec(specs.get(0));

					init(keyfactory.generatePublic(keyspec), Agreement, KeyExchange_Client_Test.iter);

					stream.write2party(keypair.getPublic().getEncoded(),
							keyagreement.generateSecret());

				}

			} catch (Exception e) {

				e.printStackTrace();

				System.exit(0);

			}
	}

	public static void main(String args[]) {

		Security.addProvider(new BouncyCastleProvider());

		KeyExchange_Server_Test server = new KeyExchange_Server_Test(8080);

		Thread t = new Thread(server);

		t.start();
	}

}
