package dkand12.CryptographicFunctions.Symmetric;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import dkand12.Helpers.returnCode;


public abstract class DiffieHellman {
	
	public static final int exponentSize = 1024; // preferred key size
	public static String ALGORITHM = null;
	private static BigInteger p = null, g = null;
	private PublicKey externalPublic = null, publicKey = null;
	private int l;
	protected AlgorithmParameterSpec paramSpec;
	private KeyPairGenerator keyGen;
	private KeyPair keyPair;
	private KeyAgreement kAgreement; /* object that takes care of the secrect key establishement. */

	protected DiffieHellman(String algorithm) {
		DiffieHellman.ALGORITHM = algorithm;	
	}
	
	protected DiffieHellman(String algorithm, AlgorithmParameterSpec spec){
		DiffieHellman.ALGORITHM = algorithm;
		if(spec!=null){
			paramSpec = spec;
			init();
		}
	}

	protected returnCode init() {
		if (paramSpec != null) {

			generatePublicPrivatkeys(); //creats a keypair instance for DH
			return returnCode.EXIT_SUCCESS;
 
		} else {
			throw new NullPointerException("paramSpec was null");
		}
	}

	/* e.g. DH or DH512 etc */
	public static DiffieHellman getInstance(String algorithm) throws NoSuchAlgorithmException{
		
		Pattern p = Pattern.compile("([A-Za-z]+)([0-9]*)");
		Matcher m = p.matcher(algorithm);
		
		if(m.find()){
			String exchangeAlgorithm = m.group(1);
			String keysize = m.group(2);
			
			if(exchangeAlgorithm.equalsIgnoreCase("DH")){
				if(!keysize.equalsIgnoreCase("")) {
					return new DH(Integer.parseInt(keysize));
				}else
					return new DH();
			} else if(exchangeAlgorithm.equalsIgnoreCase("ECDH")) {
				if(!keysize.equalsIgnoreCase("")) {
					return new EllipticCurveDiffieHellman(Integer.parseInt(keysize));
				}else
					return new EllipticCurveDiffieHellman();
			}else
				throw new NoSuchAlgorithmException(algorithm);
		} else
			throw new IllegalArgumentException(algorithm);
	}
	
	
	/** 
	 * Generates the public and private key for Diffie-Hellman keyexchange protocol. 
	 * 
	 * @return 	flags whether the method succeeded or not.
	 * @see		returnCode
	 */

	protected returnCode generatePublicPrivatkeys() {
		if (paramSpec != null) {
			KeyFactory kf;
			try {
				kf = KeyFactory.getInstance(ALGORITHM);
				keyGen = KeyPairGenerator.getInstance(ALGORITHM, "BC");
				keyGen.initialize(paramSpec);
				
				keyPair = keyGen.generateKeyPair();
				
				X509EncodedKeySpec x509spec = new X509EncodedKeySpec(keyPair.getPublic().getEncoded());
				
				publicKey = kf.generatePublic(x509spec);
				
				kAgreement = KeyAgreement.getInstance(ALGORITHM);
				kAgreement.init(keyPair.getPrivate());
				
				return returnCode.EXIT_SUCCESS;
			
			} catch (Exception e) {
				e.printStackTrace();
			}
		} else
			System.err.println("Diffie-Hellman: Either g or p was null!");

		return returnCode.EXIT_FAIL;

	}

	protected abstract AlgorithmParameterSpec generateParameters(int keysize); 

	public AlgorithmParameterSpec getParameterSpec(){
		return paramSpec;
	}
	/**
	 * Returns the public key part of the Diffie-hellman keyagreement
	 * @return 		A public key following the X509 specification 
	 * @see			DHPublicKey 	
	 */
	public PublicKey getPublicKey() {
		return publicKey;
	}

	/**
	 * getEncodedExternalKey
	 * 
	 * @return encoded external public key according to X509 spec
	 *
	 */
	
	public byte[] getEncodedExternalKey() {
		return externalPublic.getEncoded();
	}
	
	public byte[][] getParameterStream(){
		DHParameterSpec dhspec = (DHParameterSpec) paramSpec;
		
		byte[] p = dhspec.getP().toByteArray();
		byte[] g = dhspec.getG().toByteArray();
		
		return new byte[][]{p, g};
	}
	
	/**
	 * Generates the shared secret (session key) for use in the diffie hellman key exchange protocol.
	 * First argument is assumed to be Base64 encoded.
	 * 
	 * @param externalPublickey
	 * @return	The shared secret between two or more principals
	 */
	
	public byte[] generateMutulSecret(Object caller, byte[] externalPublickey) {
		KeyFactory kf;
		try {
			kf = KeyFactory.getInstance(ALGORITHM, new BouncyCastleProvider());
			
			X509EncodedKeySpec x509keySpec = new X509EncodedKeySpec(externalPublickey);
			
			if(caller instanceof EllipticCurveDiffieHellman)				//are we using ECDH?
				externalPublic = (ECPublicKey)kf.generatePublic(x509keySpec);
			else if(caller instanceof DH){
				externalPublic = kf.generatePublic(x509keySpec);
			}
			
			kAgreement.doPhase(externalPublic, true); /* last phase true */
			
			return kAgreement.generateSecret(); /* Returns a key-seed   */

		} catch(Exception e) {
			e.printStackTrace();
		}
		
		return null; // something went wrong
	}
	
	
}
