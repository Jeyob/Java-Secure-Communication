package dkand12.CryptographicFunctions.Symmetric;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECFieldElement;

import dkand12.Helpers.returnCode;

import java.io.ObjectOutputStream.PutField;
import java.security.AlgorithmParameterGenerator;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
//import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.HashMap;


/* Choose non-singular ECC curves  */

/**
 * <p><b>EllipticCurveDiffieHellman</b></p>
 * 
 * <i>Following measure must be taken in order for ECDH to work</i>
 * <table>
 * 
 * <tr><td> 1. The communicating parites must agree on a elliptic curve and a point on the curve</td></tr>
 * <tr><td> 2. The two parties then choose two private key ka and kb respectivly as privat keys </td></tr>
 * <tr><td> 3. Alice then computes ka*P (aka the addition operator for this group) and bob computes kb*P these values are exchanged.</td></tr>
 * <tr><td> 4. once they have recieved the counterparites public key they can now calculate shared secret key.
 * 		<p> BOB: 	kb*(ka*P)
 * 		<p>ALICE:	ka*(kb*P)</td></tr> 
 * 
 * </table>
 * 	<p>Because of the commutative properties these two are equal.
 * 
 * 
 */


public class EllipticCurveDiffieHellman extends DiffieHellman {

	/*
	 * ECCSTRENGTH
	 * 
	 * Used to identify the well-known elliptic curves used by the field in the
	 * ECParametes
	 * 
	 * (see: http://tools.ietf.org/html/rfc5480)
	 */
	
	public enum ECCSTRENGTH {

		EC_192(192), EC_224(224), EC_256(256), EC_384(384), EC_521(521);

		private int strength;

		private ECCSTRENGTH(int i) {
			strength = i;
		}

		public int getStrength() {
			return strength;
		}
	}
	
	private static HashMap<Integer, String> curveNames = new HashMap<Integer, String>() {
		{
			put(new Integer(192), "prime192v1");
			put(new Integer(239), "prime239v1");
			put(new Integer(256), "prime256v1");
			put(new Integer(224),"P-224");
			put(new Integer(384),"P-384");
			put(new Integer(521),"P-521");
		}
	};
	
	private int strength;
	
	
	public EllipticCurveDiffieHellman(){
		this(ECCSTRENGTH.EC_192.strength); //default value 
	}
	
	public EllipticCurveDiffieHellman(int Strength) {
		super("ECDH");
		this.strength = Strength;
		paramSpec = generateParameters(Strength);
		init();
	}
	
	public EllipticCurveDiffieHellman(ECParameterSpec eSpec) {
		super("ECDH",eSpec);
	}
	
	/**
	 * ECC parameters consist of a sixtuple T=(p,a,b,G(x1,y1),n,h)
	 * 
	 *  p: an integer specifing the finite field
	 *  
	 *  a,b: two members of the finite field given by p. These specifies the elliptic curve
	 *  
	 *  G(x1,y1): a base point on the curve 
	 *  
	 *  n: An integer specefing the order of the base point G
	 *  
	 *  h: the cofactor 
	 * 
	 */
	
	@Override
	public byte[][] getParameterStream() {
		
		try{
			return new byte[][]{curveNames.get(strength).getBytes("UTF-8")};
		}catch(Exception e){
			return new byte[][]{curveNames.get(strength).getBytes()}; /* try without UTF-8 encoding */
		}
	}
	
	
	@Override
	protected  AlgorithmParameterSpec generateParameters(int Strength) {
		ECParameterSpec spec = null;
		spec = ECNamedCurveTable.getParameterSpec(curveNames.get(new Integer(Strength)));
		return spec;
	}


}
