package TEST_MODULES;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;

import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.JDKKeyPairGenerator.DH;

public class KeyPairGeneration_Test {

	private static final int ECDH192 = 192;
	private static final int ECDH224 = 224;
	private static final int DH2056 = 2056;
	private static final int DH2783 = 2783;

	private final String[] names = new String[] { "ECDH192", "ECDH224",
			"DH2056", "DH2783" };

	private DH DHkeyGen = null;

	/* ECDH declarations */
	private ECParameterSpec ecspec;
	private KeyPairGenerator ECkeyGen = null;

	public KeyPairGeneration_Test() throws NoSuchAlgorithmException,
			NoSuchProviderException, InvalidAlgorithmParameterException {

		/* DH */
		DHkeyGen = new DH();

		/* ECDH */
		ECkeyGen = KeyPairGenerator.getInstance("ECDH");

		calc_average_time();

	}

	private void calc_average_time() {

		KeyPair keypair;

		try {

			for (int iter = 0; iter < 4; ++iter) {

				if (iter > 1) {

					DHkeyGen.initialize(iter == 2 ? DH2056 : DH2783,
							new SecureRandom());

				} else {

					ECGenParameterSpec ecspec = new ECGenParameterSpec(
							iter == 0 ? "P-192" : "P-224");

					ECkeyGen.initialize(ecspec, new SecureRandom());

				}

				int num = 10;

				/* Warm up */
				if (iter > 1) {

					for (int wRound = 0; wRound < 200; wRound++) {
						DHkeyGen.generateKeyPair();
					}

				} else {

					for (int wRound = 0; wRound < 200; wRound++) {
						ECkeyGen.generateKeyPair();
					}

				}

				/*
				 * Finding the right number of iterations such that we iterate
				 * for at least 2s
				 */
				for (;;) {

					long begin = System.currentTimeMillis();

					if ( iter > 1 ) {
						
						for ( int i = 0; i < num; i++ ) {

							keypair = DHkeyGen.generateKeyPair();
						}
					
					} else {
						
						for ( int i = 0; i < num; i++ ) {

							keypair = ECkeyGen.generateKeyPair();
						}
					}

					long end = System.currentTimeMillis();

					long time = end - begin;

					if (time >= 2000) {
						System.out.printf("%s Average keygen time: %.2f ms\n",
								names[iter], (double) time / num);
						break;
					}

					num *= 2;
				}

			}

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static void main(String args[]) throws NoSuchAlgorithmException,
			NoSuchProviderException, InvalidAlgorithmParameterException {
		Security.addProvider(new BouncyCastleProvider());
		new KeyPairGeneration_Test();

	}

}
