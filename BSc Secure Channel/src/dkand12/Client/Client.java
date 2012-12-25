package dkand12.Client;

import java.awt.BorderLayout;
import java.awt.Button;
import java.awt.Frame;
import java.awt.List;
import java.awt.TextArea;
import java.awt.TextField;
import java.awt.Window;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.Random;

import dkand12.Helpers.CipherIO;
import dkand12.Helpers.HelperMetods;

public class Client implements Runnable {

	private Socket socket;
	private BufferedOutputStream out;
	private String name;
	private CipherIO io;
	private long start; 
	@Override
	public void run() {
		Random r = new Random(System.currentTimeMillis());
		byte[] randomBytes = new byte[10];
		
		
		for (int i = 0; i < 50; ++i) {
			r.nextBytes(randomBytes);
			try {
				Thread.sleep(2000);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
			System.out.println(System.currentTimeMillis());
			io.write2party(randomBytes);
		}
	}

	public Client(String host, int port) {

		try {

			socket = new Socket(host, port);
			io = new CipherIO(socket);

		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public static void main(String args[]) throws InterruptedException {
		Thread c = new Thread(new Client("localhost", 4444));

		c.start();
		for(;;)
			Thread.sleep(5000);
	}

}
