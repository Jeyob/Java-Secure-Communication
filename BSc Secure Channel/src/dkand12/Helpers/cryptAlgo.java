package dkand12.Helpers;

import javax.crypto.SecretKey;
import java.security.spec.EllipticCurve;

public interface cryptAlgo {
	
	public byte[] Encrypt(String msg);
	public String Decrypt(byte[] cipher);
	
	public returnCode updateKey(SecretKey newKey);

}
