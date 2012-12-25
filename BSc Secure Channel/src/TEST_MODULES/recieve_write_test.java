package TEST_MODULES;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.util.encoders.Base64;

import dkand12.Helpers.HelperMetods;
import dkand12.KeyManager.CipherSetup;
import dkand12.Server.HandshakeContext.LoginContext.State;




public class recieve_write_test {
	
	private CipherSetup setup = null;
	private State CurrentState = null;
	private Socket socket = null;
	private BufferedInputStream in = null;
	private BufferedOutputStream out = null;
	private ByteArrayOutputStream byteStream = null;

	
	public recieve_write_test(Socket s){
		socket = s;
		try {
			
			in = new BufferedInputStream(s.getInputStream());
			out = new BufferedOutputStream(s.getOutputStream());
			byteStream = new ByteArrayOutputStream();
		
		} catch(IOException e){
			e.printStackTrace();
		}
	}

	public void write2client(byte[]...b) { 
		int nMsg = b.length;
		int round = 0;
		int[] partionsizes = new int[b.length];
		byteStream.reset();
		
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
		byte [] encoded = Base64.encode(HelperMetods.concatArrays(partionbytes, msgs));
		
		out.write(HelperMetods.concatArrays(HelperMetods.int2byteAry(encoded.length),encoded));
		out.flush();
		
		}catch(IOException e){
			System.err.println("Problem writing to server");
		}
	}
	
	/**
	 * recieveFromServer
	 * 
	 * reads the messages from the stream
	 * 
	 * @return	A list with message(s)
	 * 
	 */
	
	public List<byte[]> recieveFromClient(){
		
		byte[] encodedSize = new byte[4]; /* reads in the first 4 bytes that says how long the encoded msg is */
		byte[] numPartitions = new byte[4], intBuffer = new byte[4]; 
		byte[] encodedmsg = null, decodedmsg = null;
		int[] partitions;
		List<byte[]> msgList = new ArrayList<byte[]>();
		ByteArrayInputStream bufIn = null;
		
		try {
			in.read(encodedSize);
			System.out.println("Message to read (-4 bytes): "+HelperMetods.byteAry2int(encodedSize));
			
			encodedmsg = new byte[HelperMetods.byteAry2int(encodedSize)]; /* allocate storage for encoded msg */
			
			in.read(encodedmsg); //read encoded msg
			
			System.out.println("Read encoded message");
			
			decodedmsg = Base64.decode(encodedmsg);
			
			bufIn = new ByteArrayInputStream(decodedmsg);
			
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
		}catch(IOException e){
			e.printStackTrace();
			System.err.println("Problem reciving message from server");
		}
		
		return msgList;
	
	}

	
}
