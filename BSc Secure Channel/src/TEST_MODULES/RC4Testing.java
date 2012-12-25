package TEST_MODULES;

import java.security.AlgorithmParameters;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class RC4Testing {
	
	public static void main(String args[]) {
		Security.addProvider(new BouncyCastleProvider());
		
		ECKeyPairGenerator ECgenerator = new ECKeyPairGenerator();
		
		
		
	}
}
