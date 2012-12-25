package dkand12.CryptographicFunctions.Symmetric;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.spec.DHParameterSpec;

import dkand12.Helpers.Constants;

public class DH extends DiffieHellman {

	public DH() {
		this(Constants.DEFAULT_DH_KEYSIZE);
	}
	
	public DH(int keysize) {
		super("DH");
		paramSpec = generateParameters(keysize);
		init();		
	}
	
	public DH(AlgorithmParameterSpec spec) {
		super("DH",spec);
	}
	
	/**
	 * Initiates the parameters used in the diffie-hellman keyagreement. 
	 * This method is called if the object is not provided external parameters
	 *
	 */
	@Override
	protected AlgorithmParameterSpec generateParameters(int keysize) {
		DHParameterSpec spec = null;
		try {
			AlgorithmParameterGenerator apg = AlgorithmParameterGenerator
					.getInstance(ALGORITHM);
			apg.init(keysize);
			AlgorithmParameters algParam = apg.generateParameters();
			spec = (DHParameterSpec)algParam
					.getParameterSpec(DHParameterSpec.class);
			

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidParameterSpecException e) {
			e.printStackTrace();
		}
		return spec; // something went wrong
	}

}
