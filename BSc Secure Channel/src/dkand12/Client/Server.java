package dkand12.Client;

import java.awt.BorderLayout;
import java.awt.Button;
import java.awt.Frame;
import java.awt.TextArea;
import java.awt.TextField;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.List;

import dkand12.CryptographicFunctions.Symmetric.DiffieHellman;
import dkand12.Helpers.CipherIO;


public class Server implements Runnable {
	private ServerSocket server;
	private final int port = 4444;
	private Socket client;
	private CipherIO io;
	private BufferedInputStream in;
	private String name;
	private long stop;
	
	public void run() {
			System.out.println("wait connection..");
			try {
				client = server.accept(); // Accepterar inkommande anlutning(retunerar en Socket)
				
				io = new CipherIO(client);
				
				System.out.println("Connection received from "+ client.getInetAddress().getHostName());			
				
			} catch (IOException e) {
				System.err.println("Problem accepting connection request at port :"+port);
				e.printStackTrace();
				System.exit(0);

			} 

		while(true){
			List<byte[]> respons = io.recieveFromParty();
				System.out.println(System.currentTimeMillis());
//				for(int i = 0; i < respons.size(); ++i ){
//					for(byte b:respons.get(i))
//						System.out.print(b);
//					System.out.println();
//				}
		}
	}

	public Server() {
		try {
			server = new ServerSocket(port);
		} catch (IOException e) {
			e.printStackTrace();
		} // Startar en server på socket 4444
	}

	public static void main(String args[]) {
		new Thread(new Server()).start();
	}
}
	