package Communication;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.util.List;

import dkand12.Helpers.HelperMetods;
import dkand12.KeyManager.CipherSetup;

public class UDP_SERVER implements Runnable {

	private static final int DATAGRAM_BUFFERSIZE = 2048;
	private byte[] receiveBuffer = null;
	private DatagramSocket serverSocket = null;
	private DatagramPacket receiveData= null;
	private DatagramChannel serverChannel = null;
	private ByteBuffer longBuffer = null, intBuffer = null;
	private UDPdataQueue downloadQueue = null;

	public UDP_SERVER(int port,CipherSetup setup) {
		try {
			
			
			receiveBuffer = new byte[DATAGRAM_BUFFERSIZE]; /* size of message chunks */
			
			serverSocket = new DatagramSocket(port);
			
			receiveData = new DatagramPacket(receiveBuffer, receiveBuffer.length);
			
			longBuffer = ByteBuffer.allocate(8);
			
			intBuffer = ByteBuffer.allocate(4);

			downloadQueue = new UDPdataQueue();
			
			new Thread(downloadQueue).start();
			
		} catch (IOException e) {

			e.printStackTrace();
		}
	}

	@Override
	public void run() {
		
		while (true) {
			
			try{
				longBuffer.clear();
				intBuffer.clear();
				
				serverSocket.receive(receiveData); /* receive data */
				
				List<byte[]> unfolded = HelperMetods.unfoldMessage(receiveData.getData());
				
				/******* Clear previous buffers ******/
				
				longBuffer.put(unfolded.get(0));
				intBuffer.put(unfolded.get(1));
				longBuffer.rewind();
				intBuffer.rewind();
				
				/**************************************/
				
				long longval = longBuffer.getLong();
				int intval = intBuffer.getInt();
				
				UDPdatagrampacket udppacket = new UDPdatagrampacket(longval,intval ,unfolded.get(2));
		
				downloadQueue.push(udppacket); //add packet to syncronizedqueue
		
				synchronized (downloadQueue) { 
					downloadQueue.notify(); //notify worker thread if waiting.
				}
			}catch(IOException e){
				e.printStackTrace();
			}
				
			}
		}	
	}

