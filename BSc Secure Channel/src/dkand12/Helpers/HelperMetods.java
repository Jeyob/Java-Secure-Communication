package dkand12.Helpers;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.util.encoders.Base64;

import dkand12.KeyManager.CipherSetup;

public class HelperMetods {

	private enum ENDIANESS {
		LITTLE_ENDIAN, BIG_ENDIAN;
	}

	private static final ENDIANESS endianess = (ByteOrder.nativeOrder())
			.equals(ByteOrder.LITTLE_ENDIAN) ? ENDIANESS.LITTLE_ENDIAN
			: ENDIANESS.BIG_ENDIAN;

	
	public static HashSet<String> IVModes = new HashSet<String>() { // The set
																	// consisting
																	// of modes
																	// that use
																	// Initial
																	// Vector
																	// (IV)
		{
			add("CBC");
			add("OFB");
			add("CFB");
		}
	};

	public enum RSA_Mode { /*
							 * The modes supported with RSA (based on the SUNJCE
							 * provider)
							 */
		ECB("ECB");
		private String mode;

		RSA_Mode(String mode) {
			this.mode = mode;
		}

		public String value() {
			return mode;
		}
	}

	public enum RSA_Padding { /* Supported padding for RSA */

		NOPADDING("NOPADDING"), 
		PKCS1PADDING(" PKCS1PADDING"), 
		OAEPWITHMD5ANDMGF1PADDING("OAEPWITHMD5ANDMGF1PADDING"), 
		OAEPWITHSHA1ANDMGF1PADDING("OAEPWITHSHA1ANDMGF1PADDING"),
		OAEPWITHSHA_1ANDMGF1PADDING("OAEPWITHSHA-1ANDMGF1PADDING"),
		OAEPWITHSHA_256ANDMGF1PADDING("OAEPWITHSHA-256ANDMGF1PADDING"), 
		OAEPWITHSHA_384ANDMGF1PADDING("OAEPWITHSHA-384ANDMGF1PADDING"),
		OAEPWITHSHA_512ANDMGF1PADDING("OAEPWITHSHA-512ANDMGF1PADDING");

		private String type;

		private RSA_Padding(String type) {
			this.type = type;
		}

		public String value() {
			return type;
		}
	}
	
	public static byte[] generateSecureNonce() {
		return generateSecureNonce(Constants.DEFAULT_KEYSIZE);
	}
	public static byte[]  generateSecureNonce(int size) {
		SecureRandom sr = null;
		byte[] randomBytes = null;
		
		try {
			randomBytes = new byte[size];
			sr = SecureRandom.getInstance(Constants.DEFAULT_RANDOMGENERATOR_ALGORITHM);
			sr.nextBytes(randomBytes);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
		return randomBytes;
	}
	
	public static byte[] concatArrays(byte[] ary1, byte[] ary2) {
		byte[] newAry = new byte[ary1.length + ary2.length];
		System.arraycopy(ary1, 0, newAry, 0, ary1.length);
		System.arraycopy(ary2, 0, newAry, ary1.length, ary2.length);
		return newAry;
	}

	
	/**
	 * byteAry2int
	 * 
	 * A converter method, converting the bytearray to an int
	 * 
	 * @param by	A byte array
	 * @return corresponing numeric value
	 * @author http://stackoverflow.com/questions/1026761/how-to-convert-a-byte-array-to-its-numeric-value-java
	 */
	public static int byteAry2int(byte[] by){
	int value = 0;
	for (int i = 0; i < by.length; i++)
	{
	   value += ((int) by[i] & 0xffL) << (8 * i);
	}
	return value;
	}
	
	/**
	 * <b>int2byteAry</b>
	 * </br>
	 * <p>Takes a integer and creates a byte array with the least-significant byte at 
	 * the lowest address.
	 * 
	 * @param value 
	 * @return byte[] 
	 */
	
	public static byte[] int2byteAry(int value){
		ByteBuffer bf = ByteBuffer.allocate(4);
		bf.order(ByteOrder.LITTLE_ENDIAN); //since default is big endian
		bf.putInt(value);
		return bf.array();
	}
	
	public static BitSet fromArray(LinkedList<byte[]> b) {
		BitSet bits = new BitSet();
		byte[] elem = null;
		int pos = 0;
		switch (endianess) {
			case LITTLE_ENDIAN:
				for(Iterator<byte[]> it = b.iterator();it.hasNext();){
					elem = it.next();
					for (int idx = 0; idx < elem.length * 8; idx++,pos++) {
						if((elem[(int)idx/8] & (1<<idx % 8)) > 0) {
							bits.set(pos); //sets the bit (i.e. = 1)
						}
					}
				}
				break;
//TODO: Implement BIG_ENDIAN
			
			default:
				System.err.println("ENDIANESS IS UNKNOWN");
		}
		
		return bits;
	}
	
	public static BitSet fromArray(byte[] b) {
		BitSet bits = new BitSet();
		
		switch (endianess) {
			case LITTLE_ENDIAN:
					for (int idx = 0; idx < b.length * 8; idx++) {
						if((b[(int)idx/8] & (1<<idx % 8)) > 0) {
							bits.set(idx); //sets the bit (i.e. = 1)
						}
					}
					break;
//TODO: Implement BIG_ENDIAN
			
			default:
				System.err.println("ENDIANESS IS UNKNOWN");
		}
		
		return bits;
	}

	public static byte[] fromBitSet(BitSet set) {
		return null;
	}
	
	
	public static void print2console(String message){
		System.out.format("\n******* %s *******\n", message);
	}
	
	
public static List<byte[]> unfoldMessage(byte[] msg){
		
		byte[] numPartitions = new byte[4], intBuffer = new byte[4]; 
		byte[] encodedmsg = null, decodedmsg = null;
		int[] partitions;
		List<byte[]> msgList = new ArrayList<byte[]>();
		ByteArrayInputStream bufIn = null;
		
		try {
			encodedmsg = msg;
			
			//decodedmsg = Base64.decode(encodedmsg);
			
			bufIn = new ByteArrayInputStream(encodedmsg);
			
			bufIn.read(numPartitions);
			
			int nPartitions = HelperMetods.byteAry2int(numPartitions); /* {2,3,4} meaning first block is 2 byte, second 3byte and third 4 byte long */
			partitions = new int[nPartitions];
		
			for(int j = 0;j<nPartitions;j++){
				bufIn.read(intBuffer);
				partitions[j] = HelperMetods.byteAry2int(intBuffer);
			}
		
			for(int k = 0;k<nPartitions; k++){ /* store messages in arrayList */
				byte[] bytebuffer = new byte[partitions[k]];
				bufIn.read(bytebuffer);
				msgList.add(bytebuffer); /* store decoded form */ 
			}
			
			bufIn.close();
			
		}catch(IOException e){
			System.err.println("Problem unfolding message");
		}
		
		return msgList;
	
	}

	public static byte[] foldMessage(byte[]...b) { 
		int nMsg = b.length;
		int round = 0;
		int[] partionsizes = new int[b.length]; /* arrays containing the lengths of the messages to be folded */
		ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
	
		try {	
	
			do {
				byteStream.write(b[round]); /* first written array into stream is found at the beginning of the bytearray later */
				partionsizes[round] = b[round].length;
			} while((++round)<nMsg);
	
			byte[] msgs = byteStream.toByteArray();
	
			byteStream.reset();
			byteStream.write(HelperMetods.int2byteAry(partionsizes.length)); //ange hur många partitioner som finns
			for(int i = 0;i<partionsizes.length; i++) //convert the different partitions sizes to bytearrays
				byteStream.write(HelperMetods.int2byteAry(partionsizes[i]));
		
			byte[] partionbytes = byteStream.toByteArray();
			byte [] encoded = HelperMetods.concatArrays(partionbytes, msgs);
			
			return encoded;
		}catch(IOException e){
			System.err.println("Problem writing to server");
		}
		
		return null;
	}
	
	public static void printByteArray(byte[] ary){
		for(byte b:ary)
			System.out.print(b);
		System.out.println();
	}

}
