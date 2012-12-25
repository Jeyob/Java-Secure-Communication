package Communication.interfaces;

public interface CryptoObject {

	public byte[] encrypt(byte[] plaintext);
	
	public byte[] decrypt(byte[] cipertext);
	
	
}
