package TEST_MODULES;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import dkand12.CryptographicFunctions.Symmetric.EllipticCurveDiffieHellman.ECCSTRENGTH;

public class parseKeysizeTest {

	public static void main(String args[]) {
		
		
		String DH1024 = "DH1024";
		String DH = "DH";
		
		String ECDH192  = "ECDH192";
		String ECDH = "ECDH";
		
		Pattern p = Pattern.compile("([A-Za-z]+)([0-9]*)");
		Matcher m = p.matcher(ECDH);
		
		if(m.find()) 
		{
		String keysize = m.group(2);
		
		System.out.println(keysize.equalsIgnoreCase(""));
		}		
		
	}
	
}
