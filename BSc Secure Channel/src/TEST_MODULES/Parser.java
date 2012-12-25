package TEST_MODULES;

import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


class cipherSuite {
	
	private String keyExchangeAlgorithm = null;
	private String symmetricKeyAlgorithm = null;
	private String publicKeyAlgorithm = null;
	private String HashAlgorithm = null;
	private String ModeOfOperation = "NONE";
	private String SymmetricPaddingAlgorithm="NoPadding";
	private String publicPaddingAlgorithm = "NoPadding";
	
	private int publicKeySize = Integer.MIN_VALUE;;
	private int symmetricKeySize = Integer.MIN_VALUE;

	private String public_transformation;
	private String symmetric_transformation;
	
	Set<String> streamciphers = null;
	public cipherSuite() {
		streamciphers = new HashSet<String>();
		streamciphers.add("RC4");
		streamciphers.add("Verman");
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
			return getSymmetricKeyAlgorithm();
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

	
//	public String toString(){
//		return String.format("symmetric transformation:\n\t %s\npublic transformation\n\t %s\n", getSymmetric_transformation(),getPublic_transformation());
//	}
}

public class Parser {
	
	public static final int ngroups = 9;
	
			
	public static cipherSuite extractSuite(String suite){	
		cipherSuite csuite = new cipherSuite();
		
		String pattern0 = "^(DH[0-9]*|ECDH[0-9]*)_([A-Za-z]+)(_[0-9]{3,})?(_[A-Za-z0-9]+)?_WITH_([A-Za-z0-9]+)(_[0-9]+)?(_[A-Za-z]+)?(_[A-Za-z0-9]+)?_([A-Za-z]+[0-9]+$)";
		
		
		Pattern testpattern = Pattern.compile(pattern0);
		Matcher m = testpattern.matcher(suite);
		
		if(m.find()){
			
			csuite.setKeyExchangeAlgorithm(m.group(1));
			System.out.println("KEYEXCHANGE: "+m.group(1));
			csuite.setPublicKeyAlgorithm(m.group(2)); //remove leading underscore
			csuite.setPublicKeySize(m.group(3));
			csuite.setPublicPaddingAlgorithm(m.group(4));
			csuite.setSymmetricKeyAlgorithm(m.group(5));
			csuite.setSymmetricKeySize(m.group(6));
			csuite.setModeOfOperation(m.group(7));
			csuite.setSymmetricPaddingAlgorithm(m.group(8));
			csuite.setHashAlgorithm(m.group(9));
					
			}else
				System.out.println("NOT FOUND");
		
		return csuite;
		}
	
	
	
	
	public static void main(String args[]) {
		
		String suite1 = "DH1024_RSA_1024_OAEPWithSHA224AndMGF1Padding_WITH_AES_128_CBC_PKCS5Padding_SHA1";
		String suite2 = "ECDH_RSA_2048_OAEPWithSHA224AndMGF1Padding_WITH_AES_128_CBC_PKCS5Padding_SHA1";
		String suite3 =  "DH_RSA_1024_WITH_DES_64_SHA224";
		String suite4 =  "DH_RSA_WITH_RC4_SHA224";
		
		
		
		
		
		cipherSuite s = Parser.extractSuite(suite1);
	
		System.out.println(s);
		
	}

}
