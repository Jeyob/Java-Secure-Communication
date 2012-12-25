import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Security;
import java.util.Properties;
import java.util.Scanner;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import dkand12.Helpers.pair;

import Communication.ChatClient;


public class mMain {
	
	boolean exist = false;
	String username = null;
	File f = null;
	Scanner in = new Scanner(System.in);
	KeyStore keystore = null;
	Properties properties = null;
	
	public void showLoginPrompt(){
		
		try {
			keystore = KeyStore.getInstance("JKS");
			keystore.load(new FileInputStream("kStore.jks"), "password".toCharArray());
			
		do {
			System.out.print("Username: ");
			username = in.nextLine(); //read username
			String propPath = username+"/"+username+".properties";
			
			if(!new File(propPath).exists()) {
				System.out.println("Properties file for "+username+" cannot be found");
				continue;
			}
			
			if(!keystore.isKeyEntry(username)){
				System.err.println("Publickey entry could not be found for "+username);
				continue;
			}
			properties = new Properties();
			properties.load(new FileInputStream(propPath));
			
			System.out.println("\n****************************************\n");
			System.out.println("Client profile successfully identified.");
			System.out.println("\n****************************************\n");
			
			exist = true;
			
		} while(!exist);
		
		} catch (KeyStoreException e) {
			System.err.println("keystore instance is not supported");
			System.exit(1);
			
		}catch(Exception e){
			e.printStackTrace();
		}
	}
	
	public pair<String, Integer> connectionPrompt(){
	
		System.out.print("Server(IP or hostname): ");
		String ip = in.next();
	
		System.out.println();
		System.out.print("On port?: ");
		int port = in.nextInt();
		System.out.println();
		
		return new pair<>(ip, port);
		
	}
	
	
	public mMain(){
		showLoginPrompt();
		
		/* <(hostname|IP), port > */
		pair<String, Integer> tuple = connectionPrompt();

		try{
			Thread t = new Thread(new ChatClient(username, keystore, properties,tuple.x,tuple.y));
			t.start();
		}catch(Exception e){
			e.printStackTrace();
		}
		
	}

	public static void main(String args[]){
		Security.addProvider(new BouncyCastleProvider());
		new mMain();
		
	}
}
