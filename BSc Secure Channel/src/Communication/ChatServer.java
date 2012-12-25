package Communication;
import java.io.IOException;
import java.net.*;
import java.security.Security;
import java.util.concurrent.atomic.AtomicInteger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import dkand12.Helpers.STATE;

public class ChatServer implements Runnable{

	private ServerSocket server = null; 
	private Socket client = null; //Connection to the client
	private AtomicInteger nConnected = null; //number of users connected 
	
	
	public ChatServer() {
		nConnected = new AtomicInteger();
		nConnected.set(0);
	}
	
	public void run() {
		try {
			server = new ServerSocket(4444);  //Start server on socket 4444
		} catch (IOException e) {
			System.out.println("problem establishing connection port 4444");
			System.exit(0);
		}

		while(true) {
		 System.out.println("Waiting for connection..");
			try {
				client = server.accept();  //Accept incoming connections  (returns a socket)
				System.out.println("Connection received from "
						+ client.getInetAddress().getHostName());
				
				Thread t = new Thread(new ClientHandler(client, nConnected.get() > 0 ? STATE.NO_SLOTS_AVAILABLE:STATE.SLOT_PROVIDED,nConnected)); //
				t.start();
											
			} catch (IOException e) {
				System.out.println("Accept faild on port: 4444");
				e.printStackTrace();
				System.exit(0);
				
			}
		}
	}
	
	
	public static void main(String args[]) {
		Security.addProvider(new BouncyCastleProvider());
		ChatServer cs = new ChatServer();
		Thread th = new Thread(cs);
			th.start();
		}
	}

