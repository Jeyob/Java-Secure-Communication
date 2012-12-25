package dkand12.CryptographicFunctions.Public;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

public class testingRSA {
public static void main(String args[]) throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException, InvalidKeyException, InvalidAlgorithmParameterException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException{
	Security.addProvider(new BouncyCastleProvider());
	publicCrypto.RSA r = new publicCrypto.RSA("ECB","PKCS1PADDING"); 
	r.initlize(1024);
	KeyPairGenerator keygenerator = KeyPairGenerator.getInstance("RSA");
	KeyPair keypair = keygenerator.generateKeyPair();
	
	byte[] b = publicCrypto.encrypter("JONAS".getBytes(),keypair.getPublic(),"RSA","ECB","PKCS1PADDING");
	byte[] s = publicCrypto.decrypter(Base64.encode(b), keypair.getPrivate(), "RSA", "ECB", "PKCS1PADDING");

	for(byte bb:b)
		System.out.print(bb);
	System.out.println();
	System.out.println(new String(s,"UTF-8"));
}	
	
}
