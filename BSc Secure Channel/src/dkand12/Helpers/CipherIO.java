package dkand12.Helpers;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.util.encoders.Base64;

public class CipherIO {

	private Socket socket = null;
	private BufferedOutputStream out = null;
	private BufferedInputStream in = null;
	private ByteArrayOutputStream byteStream = null;
	
	
	public CipherIO(Socket socket){
		this.socket = socket;
		
		try {
			
			out = new BufferedOutputStream(socket.getOutputStream());
			in = new BufferedInputStream(socket.getInputStream());
			byteStream = new ByteArrayOutputStream();
			
		} catch(IOException e){
			e.printStackTrace();
		}
	}
	
	/**
	 * write2server
	 * 
	 * packages and encodes the messages before being sent
	 * 
	 */
	
	public void write2party(byte[]...b) { 
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
	 */
	public List<byte[]> recieveFromParty(){
		
		byte[] encodedSize = new byte[4]; /* reads in the first 4 bytes that says how long the encoded msg is */
		byte[] numPartitions = new byte[4], intBuffer = new byte[4]; 
		byte[] encodedmsg = null, decodedmsg = null;
		int[] partitions;
		List<byte[]> msgList = new ArrayList<byte[]>();
		ByteArrayInputStream bufIn = null;
		
		try {
			in.read(encodedSize);

			//System.out.println("Message to read (-4 bytes): "+HelperMetods.byteAry2int(encodedSize));
			
			encodedmsg = new byte[HelperMetods.byteAry2int(encodedSize)]; /* allocate storage for encoded msg */
			
			in.read(encodedmsg); //read encoded msg
			
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
			
			bufIn.close();
			
		}catch(IOException e){
			System.err.println("Problem reciving message from server");
		}
		
		return msgList;
	
	}

	
}
