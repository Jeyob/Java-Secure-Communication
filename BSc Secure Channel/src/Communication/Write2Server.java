package Communication;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.Socket;
import java.security.AlgorithmParameters;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.Mac;

import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

import dkand12.CryptographicFunctions.Symmetric.sCipher;
import dkand12.Helpers.CipherIO;
import dkand12.Helpers.HelperMetods;
import dkand12.KeyManager.CipherSetup;


public class Write2Server extends Thread {
	
	private static boolean BENCHMARK_ON = false;  /* set to true if benchmarking is needed */
	private static int NUMROUNDS = 50;
	private static int OVERHEAD_BASE = 10;
	
	private Socket channel = null;
	private BufferedOutputStream out = null;
	private String line = "";
	private BufferedReader br = null;
	private CipherSetup setup = null;
	private CipherIO cipherIO = null;
	private sCipher ecipher = null;
	private sCipher decipher = null;
	private HMac hmacSHA1 = null;
	private KeyParameter key = null;
	private byte[] digestContainer = null;
	private FileWriter writer = null, endToend_writer = null, overhead_writer = null;
	private long start, stop;
	
	
	public Write2Server(Socket channel, CipherSetup setup,CipherIO cipherIO) {
		this.channel = channel;
		this.setup = setup;
		this.cipherIO = cipherIO;
		
		try{
			ecipher = sCipher.getInstance(setup.getSymmetric_transformation());
			decipher = sCipher.getInstance(setup.getSymmetric_transformation());
			
			ecipher.init(Cipher.ENCRYPT_MODE, setup.getSessionKey());
	
			key = new KeyParameter(setup.getSessionKey());
			hmacSHA1 = new HMac(new SHA1Digest());
			hmacSHA1.init(key);
			
			digestContainer = new byte[hmacSHA1.getMacSize()];
			
//			writer = new FileWriter("C:\\Users\\Jonas\\Javaprograms\\Dkand12 - Project\\BSc Secure Channel\\Benchmark Data\\ClientServer_encrypt_decrypt_benchmark\\test.csv");
//			endToend_writer = new FileWriter("C:\\Users\\Jonas\\Documents\\KandidatJobbsförslag\\Benchmark_end_to_end\\end_to_end_thr1.csv");
//			overhead_writer = new FileWriter("C:\\Users\\Jonas\\Documents\\KandidatJobbsförslag\\Benchmark_overhead_analysis\\Overhead.csv");
			
		}catch(Exception e){
			e.printStackTrace();
			System.exit(MAX_PRIORITY);
		}
	}
	
	
	public void run() {
		List<byte[]> counterResponse = null;
		boolean match = false, keepGoing = true;
		BigInteger recoveredCounter = null;
		AlgorithmParameters algoparams = null;
		byte[] NULL = new byte[]{0},test1 = new byte[10], test_overhead = null;
		Random r = new Random(System.currentTimeMillis());
		
		//HelperMetods.printByteArray(test1);
		
		try {
			
//			algoparams = AlgorithmParameters.getInstance(setup.getSymmetricKeyAlgorithm());
			
			br = new BufferedReader(new InputStreamReader(System.in));
			
			int loopcount = 0;
			while(keepGoing) {
				if(!BENCHMARK_ON) {
					System.out.print("~> ");
					line = br.readLine();				
//					writer.append(line.length()+","); //for benchmarking purposes
				} else {
					//benchmark is on
//					keepGoing = (loopcount++) > NUMROUNDS ? false : true; 

				/********************** USED FOR OVERHEAD TEST *************************************/	
//					test_overhead = new byte[OVERHEAD_BASE * loopcount]; //realloc new array size
//					r.nextBytes(test_overhead); //fill array with bytes
				/***********************************************************************************/
					
//					endToend_writer.append(System.currentTimeMillis()+"\n"); //the start time. The stop is then calculated at the server side.
//					endToend_writer.flush();
					
				}
				
				start = System.currentTimeMillis();
				
				ecipher.init(Cipher.ENCRYPT_MODE, setup.getSessionKey());

				setup.counter = setup.counter.add(BigInteger.ONE);;
				
				byte[] ciphertext = null;
				byte[] counter = setup.counter.toByteArray();
				
				if(BENCHMARK_ON) {
//					r.nextBytes(test1); //fills the array with random data
//					ciphertext = ecipher.doFinal(test_overhead);
//					overhead_writer.append(test_overhead.length + "," + ciphertext.length + ",");
				}else
					ciphertext = ecipher.doFinal( HelperMetods.foldMessage(line.getBytes("UTF-8"), counter));
				
//				writer.append(ciphertext.length + ",");
				
				
				hmacSHA1.update(counter,0,counter.length);
				hmacSHA1.update(ciphertext, 0, ciphertext.length);
				hmacSHA1.doFinal(digestContainer, 0);
				
			//	System.out.format("Original message size: %d\nEncrypted message size: %d\nParameters size %d\n", line.length(), ciphertext.length, ecipher.getParameters().length);
//				if(BENCHMARK_ON){
//					overhead_writer.append((digestContainer.length+(ciphertext.length)+ecipher.getParameters().length) + "");
//					overhead_writer.append("\n");
//					overhead_writer.flush();
//				}
				
				cipherIO.write2party(ecipher.getParameters(), ciphertext, digestContainer);
				
			} //while(keepgoing)
				
		} catch (Exception e) {
				e.printStackTrace();
		} 
//		finally {
//			try {writer.close(); endToend_writer.close(); overhead_writer.close();}
//			catch(Exception e) {}
//		}
	}
}


