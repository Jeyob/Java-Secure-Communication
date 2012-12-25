package dkand12.Login.controlstation;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.Arrays;

import sun.misc.IOUtils;

import com.sun.org.apache.xml.internal.security.utils.Base64;

import dkand12.CryptographicFunctions.Public.publicCrypto;
import dkand12.Helpers.Constants;
import dkand12.Helpers.HelperMetods;

public class testServer implements Runnable {
	ServerSocket servsocket;
	Socket s = null;
	byte[] b = new byte[4];

	BufferedInputStream in = null;
	BufferedOutputStream out = null;
	ByteArrayOutputStream output;

	public testServer(int port) {
		try {
			servsocket = new ServerSocket(port);
			Thread t = new Thread(this);
			t.start();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void run() {
		try {
			s = servsocket.accept();
			System.out.println("ACCEPTED!");
			
			in = new BufferedInputStream(s.getInputStream());
			out = new BufferedOutputStream(s.getOutputStream());
			output = new ByteArrayOutputStream();
			in.read(b);
			in.read(b);
			System.out.println("READ");
			System.out.println(new String(b));
			byte[] msg = org.bouncycastle.util.encoders.Base64
					.encode(Constants.DEFAULT_AVAILABILITY_RESPONS
							.getBytes("UTF-8"));
			out.write(msg.length);
			out.write(msg);
			out.flush();
			System.out.println("SKICKAT");
			in.read(b); //how many bytes
			int byten = HelperMetods.byteAry2int(b);
			System.out.println("RECIVED "+byten);
			for(int i = 0;i<byten;i++){
				output.write(in.read());
			}
			System.out.println();

			byte[] byteary = output.toByteArray();
System.out.println("recieived: "+byteary.length+" bytes");
			for (byte bb : byteary) {
				System.out.print(bb);
			}
			System.out.println();

		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public static void main(String[] arg) {
		
		new testServer(8080);
	}

}
