package Communication;
import java.io.BufferedInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.net.*;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;

import org.bouncycastle.asn1.cms.KeyAgreeRecipientInfo;
import org.bouncycastle.asn1.cms.KeyTransRecipientInfo;
import org.bouncycastle.asn1.cms.RecipientIdentifier;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

import dkand12.CryptographicFunctions.Symmetric.sCipher;
import dkand12.Helpers.CipherIO;
import dkand12.Helpers.HelperMetods;
import dkand12.KeyManager.CipherSetup;

import Communication.interfaces.CryptoObject;

public class ReceiveFromServer implements Runnable {
	
	private BufferedInputStream in = null;
	private Socket client = null;
	private List<byte[]> message = null;
	private CipherIO cipherIO = null;
	private sCipher decipher = null;
	private sCipher ecipher = null;
	private CipherSetup setup = null;
	private HMac hmacSHA1  = null;
	private KeyParameter key;
	private byte[] digestContainer = null; 
	private FileWriter endToend_writer = null;
	int id=1;
	
	public ReceiveFromServer(Socket client, CipherIO cipherIO, CipherSetup setup) {
		
		this.client=client;
		this.cipherIO = cipherIO;
		this.setup = setup;
		
		try {
			
			in = new BufferedInputStream(client.getInputStream());
			
			decipher = sCipher.getInstance(setup.getSymmetric_transformation());
			ecipher = sCipher.getInstance(setup.getSymmetric_transformation());
			
			ecipher.init(Cipher.ENCRYPT_MODE, setup.getSessionKey());
			
			key = new KeyParameter(setup.getSessionKey());
			hmacSHA1 = new HMac(new SHA1Digest());
			hmacSHA1.init(key);
			
			digestContainer = new byte[hmacSHA1.getMacSize()]; 
			
			/****************************************************************************************************************************************/
		//	/**/ endToend_writer = new FileWriter("C:\\Users\\Jonas\\Documents\\KandidatJobbsförslag\\Benchmark_end_to_end\\end_to_end_thr2.csv");
			/****************************************************************************************************************************************/
			
		} catch (Exception e) {
			
			e.printStackTrace();
			System.exit(0);
		} 
	}
	
	public void run() {
		
		while (true) {
			byte[] NULL = new byte[]{0};
			try {
				 message = cipherIO.recieveFromParty(); /* (0) IV (1) {message, counter) (2) MessageDigest */
			
				 decipher.init(Cipher.DECRYPT_MODE, setup.getSessionKey(), Arrays.equals(message.get(0),NULL) ? null:message.get(0));
				 
				 byte[] recovered = decipher.doFinal( message.get(1) ); /* decipher message*/
				 
				 List<byte[]> unfolded = HelperMetods.unfoldMessage( recovered ); // (0) The message (1) the counter
				 BigInteger senderCounter = new BigInteger( unfolded.get(1) );
				 
				 if( senderCounter.compareTo( setup.counter ) > 0) { //Check if sendercounter is replayed
					 setup.counter = senderCounter;
				 
				 byte[] counter = setup.counter.toByteArray();
				 hmacSHA1.update(counter, 0, counter.length); /* compute expected message digest */
				 hmacSHA1.update(message.get(1), 0, message.get(1).length);
				 hmacSHA1.doFinal(digestContainer, 0);
				 
				 if(Arrays.equals(digestContainer, message.get(2))) { /* verify digest */
				 
//					 setup.counter = setup.counter.add( BigInteger.ONE ); /* expected count to be included in next message */
					 
					 
					// endToend_writer.append(System.currentTimeMillis()+"\n"); //BENCHMARK PURPOSE
					// endToend_writer.flush();
					 
					 System.out.println("Done deciphering: " + System.currentTimeMillis());
					 
//					 ecipher.init(Cipher.ENCRYPT_MODE, setup.getSessionKey());
					 
//					 cipherIO.write2party(ecipher.getParameters(), ecipher.doFinal(setup.counter.toByteArray())); /* reply to sender that counter has been successfully incremented */
					 
					 System.out.println("Received: " + new String( unfolded.get(0), "UTF-8" ));
				 }else
					 System.out.println("Message integrity check did not pass");
				 } else {
					 System.err.println(" Sender counter is not greater than local one, perhaps replayed..");
				 }
			} catch (IOException |IllegalBlockSizeException | BadPaddingException e) {
				e.printStackTrace();
				System.out.println("ReadLine failed");
				System.exit(0);
			}
		}
	}
}
