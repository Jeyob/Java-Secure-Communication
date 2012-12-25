package Communication;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.util.concurrent.ConcurrentLinkedQueue;
import dkand12.Helpers.HelperMetods;
import dkand12.Helpers.trippel;

/*
 * A UDP client as apose to the widely used TCP client (socket)
 * 
 * Performance is expected to be better using UDP than TCP, due to the missing acknowledge flag used by TCP
 * making UDP somehow faster
 * 
 * Author: Jonas Eyob 
 * Date: 2012-06-12
 * */

public class UDP_Client_Writer implements Runnable  {
	
	private DatagramSocket socket = null; 
	private int BUFFERSIZE; //Note: for UDP packets this should be no more than 8192 bytes.
	private DatagramPacket dp = null;
	private Filesystemwatcher datafetcher = null;
	private ConcurrentLinkedQueue<trippel<Long,Integer,byte[]>> dataqueue = null;
	private ByteBuffer longBuffer = null, intBuffer = null;
	
	
	int ncalls = 0;
	
	public UDP_Client_Writer(int port, InetAddress remoteHostAddress, int buffersize, int timeout) {
		
		try {
			
			longBuffer = ByteBuffer.allocate(8);
			
			intBuffer = ByteBuffer.allocate(4);
			
			BUFFERSIZE = buffersize;
			
			socket = new DatagramSocket();
			
			socket.connect(remoteHostAddress, port);
			
			socket.setSoTimeout(timeout);
			
			dp = new DatagramPacket(new byte[BUFFERSIZE], BUFFERSIZE,remoteHostAddress,port);
			
			dataqueue = new ConcurrentLinkedQueue<trippel<Long, Integer, byte[]>>();
			
			datafetcher = new Filesystemwatcher(this,"C:\\Users\\Jonas\\Javaprograms\\Dkand12 - Project\\BSc Secure Channel\\Mindstorm\\Outgoing", BUFFERSIZE-8);
			
			new Thread(datafetcher).start();
			
			
		} catch (SocketException e) {
			
			System.err.format("Problem connecting to host at: \nAddress: %s \nPort: %d", remoteHostAddress.toString(),port);
		}
	}

	public synchronized void push(trippel<Long, Integer, byte[]> item) {
		synchronized (dataqueue) {
			dataqueue.add(item);
		}
	}
	
	public synchronized trippel<Long, Integer, byte[]> pop() {
		synchronized (dataqueue) {
			return dataqueue.poll();
		}
	}
	
	@Override
	public void run() {
		
		boolean active = true;

		while(active) { /* loop until false */
			
			for(trippel<Long, Integer, byte[]> dataitem = this.pop(); dataitem!=null; dataitem = this.pop()) {
				
				longBuffer.clear(); intBuffer.clear();
				
				
				byte[] data2send = HelperMetods.foldMessage(longBuffer.putLong(dataitem.x).array(), intBuffer.putInt(dataitem.y).array(), dataitem.z);
				
				dp.setData(data2send);
				
				try {
					socket.send(dp);
				}catch (IOException e) {
					e.printStackTrace();
				}
			}
			
			synchronized (this) {
				try {
					wait();
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
			}
		}
	}
}
