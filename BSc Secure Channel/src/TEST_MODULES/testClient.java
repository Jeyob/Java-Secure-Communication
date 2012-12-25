package TEST_MODULES;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.Socket;
import org.bouncycastle.util.encoders.Base64;
import dkand12.Helpers.HelperMetods;

public class testClient  {

	private Socket socket = null;
	private BufferedOutputStream out = null;
	private ByteArrayOutputStream byteStream = null;

		
		public testClient(int portNr){
			try {
				
				socket = new Socket("192.168.1.69", portNr);
				
				System.out.println("Connected!");
				
				out = new BufferedOutputStream(socket.getOutputStream());
				byteStream = new ByteArrayOutputStream();
			
			} catch(IOException e){
				e.printStackTrace();
			}
		}
		
		/* added bookkeeping overhead is: 4 byte + (4 byte x nArguments), overhead */
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
			
			out.write(HelperMetods.concatArrays(HelperMetods.int2byteAry(encoded.length), encoded));
			out.flush();
			
			}catch(IOException e){
				System.err.println("Problem writing to server");
			}
		}
		
		
		public static void main(String args[]) throws InterruptedException {
			
			String thirdOutput = "This is highly secret...";
			
			testClient tc = new testClient(8080);
			tc.write2client(thirdOutput.getBytes());
			Thread.sleep(10000);
		}
}
