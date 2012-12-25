package dkand12.Login.controlstation;

import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import dkand12.Login.Login;

public class testPhases {
	public static void main(String[] arg){
	Security.addProvider(new BouncyCastleProvider());
		
	// Generate a 1024-bit RSA key pair
	KeyPairGenerator keyGen = null;
	PublicKey publicKey; 
	PrivateKey privateKey;
	KeyPair keypair;
	
	try {
		keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(1024);
		keypair = keyGen.genKeyPair();
		privateKey = keypair.getPrivate();
		publicKey = keypair.getPublic();
		
		Socket s = new Socket("localhost", 8080);
		
		Login l = new Login("Jonas", publicKey, new cPhase_one(), s, "ECB","PKCS1Padding");
		for(int i = 0;i<2;i++)
		 l.doPhase();
		for(;;);
	} catch (NoSuchAlgorithmException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (UnknownHostException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (IOException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (NoSuchProviderException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (NoSuchPaddingException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	}
}
