package TEST_MODULES;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.asymmetric.ec.KeyFactory;
import org.bouncycastle.jce.provider.asymmetric.ec.KeyPairGenerator;
import org.bouncycastle.jce.spec.ECParameterSpec;

import sun.security.ec.ECDHKeyAgreement;
import sun.security.ec.ECParameters;

import dkand12.Helpers.HelperMetods;

public class cleanDiffieHellman {
	
	public static AlgorithmParameterSpec generateECDHParameters(int keysize) {
		try {
			
			KeyPairGenerator keyGen = new KeyPairGenerator.ECDH();
			keyGen.initialize(keysize);
			KeyPair pair = keyGen.generateKeyPair();
			ECPublicKey pub = (ECPublicKey)pair.getPublic();
			ECPrivateKey pri = (ECPrivateKey)pair.getPrivate();
			
			java.security.spec.ECParameterSpec specpub = pub.getParams();
			java.security.spec.ECParameterSpec specpri = pri.getParams();
			
			System.out.println(specpri.getOrder());
			System.out.println(specpub.getOrder());
		
			System.out.println(specpri.getGenerator().getAffineX());
			System.out.println(specpub.getGenerator().getAffineX());
			
			System.out.println(specpri.getGenerator().getAffineY());
			System.out.println(specpub.getGenerator().getAffineY());
			
			System.out.println(specpri.getCofactor());
			System.out.println(specpub.getCofactor());
			
			System.out.println(specpri.getCurve().getA());
			System.out.println(specpub.getCurve().getA());
			
			System.out.println(specpri.getCurve().getB());
			System.out.println(specpub.getCurve().getB());
			
		}catch(Exception e){
			e.printStackTrace();
		}
		
		return null;
		
	}
	
	public static void main(String args[]) {
		Security.addProvider(new BouncyCastleProvider());
		String algorithm = "ECDH";
		
		try {
			
			cleanDiffieHellman.generateECDHParameters(192);
			
			java.security.KeyPairGenerator keyGen1 = KeyPairGenerator.getInstance(algorithm);
			java.security.KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm);
			
			keyGen.initialize(192);
			keyGen1.initialize(192);
			
			
			for(int round = 0; round<50;round++) {
				
				long start = System.currentTimeMillis();
				KeyPair pair = keyGen.generateKeyPair();
				
				KeyPair pair1 = keyGen1.generateKeyPair();

				byte[] agreementPublic = pair.getPublic().getEncoded();
				byte[] agreementPublic1 = pair1.getPublic().getEncoded();
				
				X509EncodedKeySpec spec1 = new X509EncodedKeySpec(agreementPublic1);
				X509EncodedKeySpec spec = new X509EncodedKeySpec(agreementPublic);
				
				java.security.KeyFactory kf = java.security.KeyFactory.getInstance(algorithm);
				
				PublicKey key1 = kf.generatePublic(spec1);
				PublicKey key = kf.generatePublic(spec);
				
				
				KeyAgreement agreement = KeyAgreement.getInstance(algorithm);
				KeyAgreement agreement1 = KeyAgreement.getInstance(algorithm);
				
				agreement.init(pair.getPrivate());
				agreement.doPhase(pair1.getPublic(), true);
				
				agreement1.init(pair1.getPrivate());
				agreement1.doPhase(pair.getPublic(), true);
				
				byte[] k = agreement.generateSecret();
				byte[] kk = agreement1.generateSecret();
			
				long stop = System.currentTimeMillis();
				System.out.println(stop-start);
		}	
			
//			System.out.println(k.length);
//			System.out.println(kk.length);
//			HelperMetods.printByteArray(k);
//			HelperMetods.printByteArray(kk);
//			
		}catch(Exception e) {
			e.printStackTrace();
		}
		
	}

}
