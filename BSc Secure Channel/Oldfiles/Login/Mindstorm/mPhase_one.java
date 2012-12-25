package dkand12.Login.Mindstorm;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.bouncycastle.cert.X509CertificateHolder;

import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;
import com.sun.org.apache.xml.internal.security.utils.Base64;

import dkand12.Helpers.Constants;
import dkand12.Helpers.HelperMetods;
import dkand12.Login.Login;
import dkand12.Server.HandshakeContext.LoginContext.sState;

public class mPhase_one implements sState { 
 private KeyStore users=null;
	@Override
	public byte[] nextPhase(Login protocol)  {
		
		
		byte[] msg, responseMsg = null, encryptedNonce = null;
		ByteArrayOutputStream bos = null;
		String username = null;
	
		/********************** part 1 ****************************/
		try {
			msg = org.bouncycastle.util.encoders.Base64
					.encode(Constants.DEFAULT_AVAILABILITY_RESPONS
							.getBytes("UTF-8"));
			
			protocol.write2socket(msg);		
			
			responseMsg = Base64.decode(protocol.readSocket()); 
			
			//extract username
			int username_length =  HelperMetods.byteAry2int(Arrays.copyOfRange(responseMsg, 0, 3));
			
			bos = new ByteArrayOutputStream(username_length);
			for(int j =  4; j<username_length; j++){
				bos.write(responseMsg[j]);
			}
			
			username = new String(bos.toByteArray());
			
			//extract encrypted secret nonce
			
			bos = new ByteArrayOutputStream(responseMsg.length - username_length - 4); 
			for(int k=username_length + 4 - 1, j = responseMsg.length-username_length-4;k<j;k++){
				bos.write(responseMsg[k]);
			}
			
			encryptedNonce = bos.toByteArray();
			

			
		} catch (Exception e){
			e.printStackTrace();
			System.exit(0);
		}
		
		return null;
	
	}

}
 