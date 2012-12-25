package dkand12.KeyManager;

import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


public final class CipherSetup {
	
	private final int KEYEXCHANGE = 1;
	private final int PUBLICKEY_ALGORITHM = 2;
	private final int PUBLICKEY_SIZE = 3;
	private final int PUBLICPADDINGALGORITHM = 4;
	private final int SYMMETRICKEY_ALGORITHM = 5;
	private final int SYMMETRICKEY_SIZE = 6;
	private final int MODE_OF_OPERATION = 7;
	private final int SYMMETRICPADDINGALGORITHM = 8;
	private final int HASHALGORITHM = 9;
	

	//symmetric key
	private String symmetricKeyAlgorithm = null;
	private String ModeOfOperation = "NONE";
	private String SymmetricPaddingAlgorithm="NoPadding";
	private int symmetricKeySize = Integer.MIN_VALUE;

	//public key 
	private String publicKeyAlgorithm=null;
	private int publicKeySize = Integer.MIN_VALUE;;
	private String publicPaddingAlgorithm = null;

	//transformations
	private String public_transformation;
	private String symmetric_transformation;
	
	//Hash
	private String HashAlgorithm = null;

	Set<String> streamciphers = null;
	private Map<String, Integer> defaultKeysizes = null;
	
	//Keyexchange
	private String keyExchangeAlgorithm = null;

	private SecretKey secretKey;
	private PublicKey myPublicKey = null;
	private PrivateKey myPrivateKey = null;
	private PublicKey otherPublicKey = null;
	private Properties properties = null;
	private KeyStore keystore = null;
	private String username = null, opponentName = null;
	private String recipient_name = null;
	private byte[] sessionKey = null;
	private long freshnessCount = Long.MIN_VALUE;
	private List<String> supportedCiphers = null;
	public BigInteger counter = null; 
	
	
	
	public CipherSetup(String username, Properties prop, KeyStore store){
		properties = prop;
		keystore = store;
		this.username = username;
		
		/* streamciphers */
		streamciphers = new HashSet<String>();
		streamciphers.add("RC4");
		streamciphers.add("Verman");
		
		/* default keysizes */
		defaultKeysizes = new HashMap<String, Integer>(){
			{
				put("AES", 128);
				put("DES", 64);
				put("RSA", 1024);
			
			}
		};
		
		loadPublicPrivateKeys();
		
		initlizeCipherSet(prop.getProperty("supported_ciphers"));
	}
	
	private void loadPublicPrivateKeys(){
		try{
			Key key = keystore.getKey(username, "password".toCharArray());
			if(key instanceof PrivateKey){
			
				Certificate c = keystore.getCertificate(username);
			
				myPublicKey = c.getPublicKey();
				myPrivateKey = (PrivateKey) key;
			}
			
			if(!username.equalsIgnoreCase("mindstorm"))
				setOtherPublicKey(keystore.getCertificate("mindstorm").getPublicKey());

			
		} catch (KeyStoreException e) {
				e.printStackTrace();
		} catch (UnrecoverableKeyException e) {
				e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			}
		}
		
	private void initlizeCipherSet(String ciphers){
		supportedCiphers = new LinkedList<String>(Arrays.asList(ciphers.split(",")));
	}
	
	public Iterator<String> getSupportedCiphers(){
		return supportedCiphers.iterator();
	}

	public String getUsername(){
		return username;
	}

	public void fromCipherSuite(String suite) {
		
		//extract different parts of the String
		
		String pattern0 = "^(DH[0-9]*|ECDH[0-9]*)_([A-Za-z]+)(_[0-9]{3,})?(_[A-Za-z0-9]+)?_WITH_([A-Za-z0-9]+)(_[0-9]+)?(_[A-Za-z]+)?(_[A-Za-z0-9]+)?_([A-Za-z]+[0-9]+$)";
		
		
		Pattern testpattern = Pattern.compile(pattern0);
		Matcher m = testpattern.matcher(suite);
		
		if(m.find()){
			
			this.setKeyExchangeAlgorithm(m.group(KEYEXCHANGE));
			this.setPublicKeyAlgorithm(m.group(PUBLICKEY_ALGORITHM));
			this.setPublicKeySize(m.group(PUBLICKEY_SIZE));
			this.setPublicPaddingAlgorithm(m.group(PUBLICPADDINGALGORITHM));
			this.setSymmetricKeyAlgorithm(m.group(SYMMETRICKEY_ALGORITHM));
			this.setSymmetricKeySize(m.group(SYMMETRICKEY_SIZE));
			this.setModeOfOperation(m.group(MODE_OF_OPERATION));
			this.setSymmetricPaddingAlgorithm(m.group(SYMMETRICPADDINGALGORITHM));
			this.setHashAlgorithm(m.group(HASHALGORITHM));
					
			}
		}
	
	
	public String getKeyExchangeAlgorithm() {
		return keyExchangeAlgorithm;
	}

	public void setKeyExchangeAlgorithm(String keyExchangeAlgorithm) {
		this.keyExchangeAlgorithm = keyExchangeAlgorithm;
	}

	public String getSymmetricKeyAlgorithm() {
		return symmetricKeyAlgorithm;
	}

	public void setSymmetricKeyAlgorithm(String symmetricKeyAlgorithm) {
		this.symmetricKeyAlgorithm = symmetricKeyAlgorithm;
	}

	public String getPublicKeyAlgorithm() {
		return publicKeyAlgorithm;
	}

	public void setPublicKeyAlgorithm(String publicKeyAlgorithm) {
		this.publicKeyAlgorithm = publicKeyAlgorithm.replaceAll("_", "");
	}

	public String getHashAlgorithm() {
		return HashAlgorithm;
	}

	public void setHashAlgorithm(String hashAlgorithm) {
		HashAlgorithm = hashAlgorithm.replaceAll("_", "");
	}

	public String getModeOfOperation() {
		return ModeOfOperation;
	}

	public void setModeOfOperation(String modeOfOperation) {
		if(modeOfOperation!=null)
			ModeOfOperation = modeOfOperation.replaceAll("_","");
		else
			ModeOfOperation = "NONE";
	}

	public String getSymmetricPaddingAlgorithm() {
		return SymmetricPaddingAlgorithm;
	}

	public void setSymmetricPaddingAlgorithm(String symmetricPaddingAlgorithm) {
		if(symmetricPaddingAlgorithm!=null)
			SymmetricPaddingAlgorithm = symmetricPaddingAlgorithm.replaceAll("_", "");
		else
			SymmetricPaddingAlgorithm = "NoPadding";
	}

	public String getPublicPaddingAlgorithm() {
		return publicPaddingAlgorithm;
	}

	public void setPublicPaddingAlgorithm(String publicPaddingAlgorithm) {
		if(publicPaddingAlgorithm!=null)
		this.publicPaddingAlgorithm = publicPaddingAlgorithm.replaceAll("_", "");
		else
			this.publicPaddingAlgorithm = "NoPadding";
	}

	public int getPublicKeySize() {
		return publicKeySize;
	}

	public void setPublicKeySize(String publicKeySize) {
		if(publicKeySize!=null)
			this.publicKeySize = Integer.parseInt(publicKeySize.replaceAll("_", ""));
		else
			this.publicKeySize = Integer.MIN_VALUE;
	}

	public int getSymmetricKeySize() {
		return symmetricKeySize;
	}

	public void setSymmetricKeySize(String symmetricKeySize) {
		if(symmetricKeySize!=null)
			this.symmetricKeySize = Integer.parseInt(symmetricKeySize.replaceAll("_", ""));
		else
			this.symmetricKeySize = Integer.MIN_VALUE;
	}

	public String getPublic_transformation() {
		return getPublicKeyAlgorithm()+"/"+"NONE/"+getPublicPaddingAlgorithm();
	}

	public String getSymmetric_transformation() {
		if(!streamciphers.contains(getSymmetricKeyAlgorithm()))
			return getSymmetricKeyAlgorithm()+"/"+getModeOfOperation()+"/"+getSymmetricPaddingAlgorithm();
		else
			return getSymmetricKeyAlgorithm()+"/"+getHashAlgorithm();
	}

	@Override
	public String toString() {
		return "cipherSuite [keyExchangeAlgorithm=" + keyExchangeAlgorithm
				+ ", \nsymmetricKeyAlgorithm=" + symmetricKeyAlgorithm
				+ ", \npublicKeyAlgorithm=" + publicKeyAlgorithm
				+ ", \nHashAlgorithm=" + HashAlgorithm + ", \nModeOfOperation="
				+ ModeOfOperation + ", \nSymmetricPaddingAlgorithm="
				+ SymmetricPaddingAlgorithm + ", \npublicPaddingAlgorithm="
				+ publicPaddingAlgorithm + ", \npublicKeySize=" + publicKeySize
				+ ", \nsymmetricKeySize=" + symmetricKeySize
				+ ", \npublic_transformation=" + public_transformation
				+ ", \nsymmetric_transformation=" + symmetric_transformation
				+ ", \nstreamciphers=" + streamciphers + "]";
	}

	public KeyStore getKeyStore(){
		return keystore;
	}
	
	public Properties getProperties(){
		return properties;
	}
	

	public PublicKey getMyPublicKey() {
		return myPublicKey;
	}

	public void setMyPublicKey(PublicKey myPublicKey) {
		this.myPublicKey = myPublicKey;
	}

	public PrivateKey getMyPrivateKey() {
		return myPrivateKey;
	}

	public void setMyPrivateKey(PrivateKey myPrivateKey) {
		this.myPrivateKey = myPrivateKey;
	}

	public PublicKey getOtherPublicKey() {
		return otherPublicKey;
	}

	public void setOtherPublicKey(PublicKey otherPublicKey) {
		this.otherPublicKey = otherPublicKey;
	}

	public String getRecipient_name() {
		return recipient_name;
	}

	public void setRecipient_name(String recipient_name) {
		this.recipient_name = recipient_name;
	}

	public byte[] getSessionKey() {
		return sessionKey;
	}

	public void setSessionKey(byte[] sessionKey) {
		this.sessionKey = sessionKey;
	}

	public long getFreshnessCount() {
		return freshnessCount;
	}

	public void setFreshnessCount(long freshnessCount) {
		this.freshnessCount = freshnessCount;
	}
	
}
