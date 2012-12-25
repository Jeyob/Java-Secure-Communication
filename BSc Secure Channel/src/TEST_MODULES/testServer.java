package TEST_MODULES;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Arrays;
import java.util.List;

/* This class is used as a way of testing the correctness of our application
 * 
 * Purpose: send messages encrypted 
 * 
 *      
 *   */


public class testServer implements Runnable {

	ServerSocket serversocket = null;
	Socket socket = null;
	recieve_write_test rw = null;
	
	public testServer(){
		try {
			serversocket = new ServerSocket(8080);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	
	@Override
	public void run() {
		// TODO Auto-generated method stub
		
		try {

			socket = serversocket.accept();
			rw = new recieve_write_test(socket);
			
			List<byte[]> lst = rw.recieveFromClient();
			System.out.println("RECEIVED DATA!");
			
			assert !Arrays.equals(lst.get(0), "ONE".getBytes()): "MATCH";
			System.out.println(new String(lst.get(0)));
			
			lst = rw.recieveFromClient();
			assert Arrays.equals(lst.get(0), "ONE".getBytes()) && Arrays.equals(lst.get(1), "TWO".getBytes()): "MATCH";
			System.out.println(new String(lst.get(1)));
			
			lst = rw.recieveFromClient();
			assert Arrays.equals(lst.get(0), "ONE".getBytes()) && Arrays.equals(lst.get(1), "TWO".getBytes()) && Arrays.equals(lst.get(2), "THREE".getBytes()): "MATCH";
			System.out.println(new String(lst.get(2)));
			
			//rw.recieveFromClient();
			
		} catch (IOException e) {
			e.printStackTrace();
		}
		
	}
	
	public static void main(String args[]){
		new Thread(new testServer()).start();
	}

}
