package TEST_MODULES;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.JDKKeyPairGenerator.DH;
import org.bouncycastle.jce.provider.asymmetric.ec.KeyPairGenerator;
import org.bouncycastle.jce.spec.ECParameterSpec;

import com.sun.crypto.provider.DHKeyPairGenerator;

public class BouncyECDH_VS_SunECDH {

	java.security.KeyPairGenerator keyPairGenerator;

	public BouncyECDH_VS_SunECDH() throws NoSuchAlgorithmException {
		generateKeys();
	}

	private void generateKeys() {

		KeyPair keypair;

		try {
			System.out.println(Cipher.getMaxAllowedKeyLength("RSA"));
			
			DH dhkeygen = new DH();
			dhkeygen.initialize(2048);
			dhkeygen.generateKeyPair();
			
			ECGenParameterSpec ecspec = new ECGenParameterSpec("P-192");
			keyPairGenerator = java.security.KeyPairGenerator.getInstance("ECDH");
//			ECParameterSpec espec = ECNamedCurveTable.getParameterSpec("P-224");
			keyPairGenerator.initialize(ecspec, new SecureRandom());

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

	public static void main(String args[]) throws NoSuchAlgorithmException {
		Security.addProvider(new BouncyCastleProvider());
		new BouncyECDH_VS_SunECDH();
	}

}
