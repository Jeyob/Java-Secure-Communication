package TEST_MODULES;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.symmetric.AES.KeyGen;

import dkand12.CryptographicFunctions.Symmetric.VermanDigest;
import dkand12.CryptographicFunctions.Symmetric.sCipher;

public class Encryption_AND_Decryption_BENCHMARK {

	private static boolean PUBLIC_CRYPTO_TEST_ENABLED = true;

	byte[][] randomDataVector = null;
	byte[][] publicCrypto_testvector = null;

	public Encryption_AND_Decryption_BENCHMARK() {

		Random rnd = new Random(System.currentTimeMillis());
		byte[] nbytes_1600 = new byte[1600 * 16];
		byte[] nbytes_4800 = new byte[4800 * 16];
		byte[] nbytes_11200 = new byte[11200 * 16];
		byte[] nbytes_14400 = new byte[14400 * 16];
		byte[] nbytes_17600 = new byte[17600 * 16];
		byte[] nbytes_20800 = new byte[20800 * 16];
		byte[] nbytes_24000 = new byte[24000 * 16];
		byte[] nbytes_27200 = new byte[27200 * 16];
		byte[] nbytes_30400 = new byte[30400 * 16];
		byte[] nbytes_32700 = new byte[32700 * 16];
		byte[] nbytes_34600 = new byte[34600 * 16];

		rnd.nextBytes(nbytes_1600);
		rnd.nextBytes(nbytes_4800);
		rnd.nextBytes(nbytes_11200);
		rnd.nextBytes(nbytes_14400);
		rnd.nextBytes(nbytes_17600);
		rnd.nextBytes(nbytes_20800);
		rnd.nextBytes(nbytes_24000);
		rnd.nextBytes(nbytes_27200);
		rnd.nextBytes(nbytes_30400);
		rnd.nextBytes(nbytes_32700);
		rnd.nextBytes(nbytes_34600);

		byte[] nbytes_2 = new byte[2*8]; //64bit * var
		byte[] nbytes_4 = new byte[4*8];
		byte[] nbytes_6 = new byte[6*8];
		byte[] nbytes_8 = new byte[8*8];
		byte[] nbytes_10 = new byte[10*8];

		randomDataVector = new byte[][] { nbytes_1600, nbytes_4800,
				nbytes_11200, nbytes_14400, nbytes_17600, nbytes_20800,
				nbytes_24000, nbytes_27200, nbytes_30400, nbytes_32700,
				nbytes_34600 };

		publicCrypto_testvector = new byte[][] { nbytes_2, nbytes_4,
				nbytes_6, nbytes_8, nbytes_10 };
	}

	public static void main(String args[]) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		Cipher AES128 = null, AES256 = null, DES = null, RSA512 = null, RSA1024 = null, RSA2048 = null;
		sCipher vermanSHA1 = null;
		KeyGenerator keyGen = null;
		KeyPairGenerator pubKeyGen = null;
		SecretKey AES128_key, AES256_key, DES_key;
		Key _RSA512, _RSA1024, _RSA2048;
		File file = null;
		Calendar calender = null;
		SimpleDateFormat sdf = null;
		String sessionFolder = null;

		Encryption_AND_Decryption_BENCHMARK edb = new Encryption_AND_Decryption_BENCHMARK();

		try {

			calender = Calendar.getInstance();
			sdf = new SimpleDateFormat("yyyyMMdd'T'HHmmss");

			sessionFolder = "C:\\Users\\Jonas\\Javaprograms\\Dkand12 - Project\\BSc Secure Channel\\Benchmark Data\\benchmark_"
					+ sdf.format(calender.getTime());
			file = new File(sessionFolder);
			file.mkdir();

			keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(128);
			AES128_key = keyGen.generateKey();

			keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(256);
			AES256_key = keyGen.generateKey();

			keyGen = KeyGenerator.getInstance("DES");
			DES_key = keyGen.generateKey();

			// pubKeyGen = KeyPairGenerator.getInstance("RSA","BC");
			// pubKeyGen.initialize(512);
			// _RSA512 = pubKeyGen.generateKeyPair().getPublic();
			//
			pubKeyGen = KeyPairGenerator.getInstance("RSA", "BC");
			pubKeyGen.initialize(1024);
			_RSA1024 = pubKeyGen.generateKeyPair().getPublic();

			pubKeyGen = KeyPairGenerator.getInstance("RSA", "BC");
			pubKeyGen.initialize(2048);
			_RSA2048 = pubKeyGen.generateKeyPair().getPublic();

			AES128 = Cipher.getInstance("AES/CBC/NoPadding");
			AES128.init(Cipher.ENCRYPT_MODE, AES128_key);

			DES = Cipher.getInstance("DES/CBC/NoPadding");
			DES.init(Cipher.ENCRYPT_MODE, DES_key);

			vermanSHA1 = sCipher.getInstance("Verman/SHA1");
			vermanSHA1.init(sCipher.ENCRYPT, SecureRandom.getSeed(128));

			// RSA512 =
			// Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding","BC");
			// RSA512.init(Cipher.ENCRYPT_MODE, _RSA512);

			RSA1024 = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding",
					"BC");
			RSA1024.init(Cipher.ENCRYPT_MODE, _RSA1024);

			RSA2048 = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding",
					"BC");
			RSA2048.init(Cipher.ENCRYPT_MODE, _RSA2048);

			if (!PUBLIC_CRYPTO_TEST_ENABLED) {
				System.out.println("Begin AES 128");
				edb.createCSVFile(AES128, sessionFolder, "AES128");
				System.out.println("Begin DES");
				edb.createCSVFile(DES, sessionFolder, "DES");
				System.out.println("Begin vernman");
				edb.createCSVFile(vermanSHA1, sessionFolder, "VermanSHA1");

			} else {
				// System.out.println("Begin RSA512");
				// edb.createCSVFile(RSA512, sessionFolder, "RSA512");
				System.out.println("Begin RSA1024");
				edb.createCSVFile(RSA1024, sessionFolder, "RSA1024");
				System.out.println("Begin 2048");
				edb.createCSVFile(RSA2048, sessionFolder, "RSA2048");

			}
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(0);
		}
	}

	public void createCSVFile(sCipher encrypter, String dirPath, String filename)
			throws Exception {
		long e_start, e_stop, d_start, d_stop;
		FileWriter writer = new FileWriter(dirPath + "\\" + filename + ".csv");

		for (int times = 0; times < 100; times++) {
			for (byte[] rndVector : (PUBLIC_CRYPTO_TEST_ENABLED ? publicCrypto_testvector
					: randomDataVector)) {
				e_start = System.currentTimeMillis();
				encrypter.doFinal(rndVector);
				e_stop = System.currentTimeMillis();
				writer.append(e_stop - e_start + "");
				writer.append(',');
			}
			writer.append('\n');
			writer.flush();
		}
	}

	public void createCSVFile(Cipher encrypter, String dirPath, String filename)
			throws Exception {
		long e_start, e_stop, d_start, d_stop;
		FileWriter writer = new FileWriter(dirPath + "\\" + filename + ".csv");

		for (int times = 0; times < 100; times++) {
			for (byte[] rndVector : (PUBLIC_CRYPTO_TEST_ENABLED ? publicCrypto_testvector:randomDataVector)) {
				e_start = System.currentTimeMillis();
				System.out.println("rndvector"+rndVector.length);
				encrypter.doFinal(rndVector);
				e_stop = System.currentTimeMillis();
				writer.append(e_stop - e_start + "");
				writer.append(',');
			}
			writer.append('\n');
			writer.flush();
		}
	}
}
