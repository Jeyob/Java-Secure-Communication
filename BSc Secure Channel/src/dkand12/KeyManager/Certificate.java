package dkand12.KeyManager;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Date;

import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.*;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import dkand12.Helpers.Constants;
import sun.font.CreatedFontTracker;
import sun.security.rsa.RSAKeyFactory;
import sun.security.x509.X500Name;

public class Certificate implements Serializable{
	/**
	 * 
	 */
	private static final long serialVersionUID = -131182716452382386L;
	/**
	 * Class for creating certificate according to X509 standard
	 * 
	 */

	private KeyPairGenerator keyPairGenerator = null;
	private KeyPair keyPair = null;
	private X509v3CertificateBuilder v3CertBuilder = null;
	private SubjectPublicKeyInfo publicKeyInfo = null;
	private ContentSigner contentSigner = null;
	private X509CertificateHolder certHolder = null;

	private Certificate(String name, String algorithm, int keysize) throws NoSuchAlgorithmException, OperatorCreationException {

		Date startDate = new Date(System.currentTimeMillis() - 24 * 60 * 60
				* 1000); // code snippet from example:
							// http://www.bouncycastle.org/wiki/display/JA1/BC+Version+2+APIs
		Date endDate = new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60
				* 1000); // code snippet from example:
							// http://www.bouncycastle.org/wiki/display/JA1/BC+Version+2+APIs

		keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
		keyPairGenerator.initialize(keysize);
		keyPair = keyPairGenerator.generateKeyPair();
		
		System.out.println(keyPair.getPublic());

		contentSigner = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(keyPair.getPrivate()); //self signing
		
		publicKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic()
				.getEncoded());
		
		v3CertBuilder = new X509v3CertificateBuilder(
				new org.bouncycastle.asn1.x500.X500Name("CN=MINDSTORM"),
				BigInteger.valueOf(new SecureRandom().nextInt()), startDate,
				endDate, new org.bouncycastle.asn1.x500.X500Name("CN="+name),
				publicKeyInfo);
		
		certHolder = v3CertBuilder.build(contentSigner); //build certificate..
		
	}

	public static Certificate CertificateFactory(String name, int keySize) {
		return CertificateFactory(name, Constants.DEFAULT_PUBLICKEY_SCHEME,
				keySize);
	}

	public static Certificate CertificateFactory(String name, String algorithm, int keySize) {
		Certificate cert = null;
		try {
			
			cert = new Certificate(name, algorithm, keySize);
			
		} catch (NoSuchAlgorithmException | OperatorCreationException e) {
			
			e.printStackTrace();
			System.exit(0);
		}
		
		return cert;
	}
	
	public PublicKey getPublicKey() throws IOException{
		try{
			SubjectPublicKeyInfo subjectPubKey = certHolder.getSubjectPublicKeyInfo();	
			RSAKeyParameters rsaParam = (RSAKeyParameters)PublicKeyFactory.createKey(subjectPubKey);
			RSAPublicKeySpec rsaSpec = new RSAPublicKeySpec(rsaParam.getModulus(), rsaParam.getExponent());
			KeyFactory keyfactory = KeyFactory.getInstance("RSA");
			return keyfactory.generatePublic(rsaSpec);
		} 
		catch(Exception e){
			e.printStackTrace();		
		}
		
		return null;
	}

	public X509CertificateHolder getCertHolder(){
		return certHolder;
	}
	
	
	public static void main(String[] args){ /* Testing */
		Security.addProvider(new BouncyCastleProvider());
		try {
			Certificate cert = Certificate.CertificateFactory("Jonas", 1024);
			FileOutputStream fos = new FileOutputStream("certobj");
			ObjectOutputStream oos = new ObjectOutputStream(fos);
			oos.writeObject(cert);
			oos.close();
			
			FileInputStream fis = new FileInputStream("certobj");
			ObjectInputStream ois = new ObjectInputStream(fis);
			
			Certificate cert2 = (Certificate)ois.readObject();
			
			
			System.out.println(cert2.getPublicKey());
			
			fos.write(cert.getCertHolder().getEncoded());
			fos.close();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}
		
	}
	
}
