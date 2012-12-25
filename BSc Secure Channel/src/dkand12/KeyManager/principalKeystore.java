package dkand12.KeyManager;

import javax.crypto.SecretKey;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Enumeration;


public class principalKeystore {

	java.io.File file;
	private KeyStore store;
	private final String keyStoreName, alias;
	private final char[] password;
	private BufferedOutputStream outStream;

	public principalKeystore(String alias, char[] password) // alias is the
															// username
			throws FileNotFoundException {
		this.alias = alias;
		keyStoreName = this.alias + ".jks";
		this.password = password;
		try {
			file = new File(keyStoreName);
			if (!file.exists()) // file does not exist create it
				file.createNewFile();

			FileInputStream inStream = new FileInputStream(keyStoreName);
			store = KeyStore.getInstance("JCEKS"); // we use this instance to
													// that secretkeyentry work

			if (inStream.available() > 0)
				store.load(inStream, password);
			else
				store.load(null, password);
			inStream.close(); // close stream

		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
	}

	public SecretKey getSecretKey(String alias) {
		try {
			if (store.isKeyEntry(alias))
				return (SecretKey) store.getKey(alias, password);
		} catch (UnrecoverableKeyException e) {
			e.printStackTrace();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		return null;
	}

	public PublicKey getPublic(String alias) {
		Key k;
		try {
			if (store.isKeyEntry(alias)) {
				if ((k = store.getKey(alias, password)) instanceof PublicKey)
					return (PublicKey) k;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}
	
	public PrivateKey getPrivateKey(String alias){
		Key k;
		try {
			if (store.isKeyEntry(alias)) {
				if ((k = store.getKey(alias, password)) instanceof PrivateKey)
					return (PrivateKey) k;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	public void addSecretKeyEntry(String alias, KeyStore.SecretKeyEntry entry) {

		try {

			outStream = new BufferedOutputStream(new FileOutputStream(
					keyStoreName, true));
			store.setEntry(alias, entry, new KeyStore.PasswordProtection(
					password));
			store.store(outStream, password);
			outStream.close();

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public void addPrivatKeyEntry(String alias, KeyStore.PrivateKeyEntry entry) {
		try {
			outStream = new BufferedOutputStream(new FileOutputStream(
					keyStoreName, true));
			store.setEntry(alias, entry, new KeyStore.PasswordProtection(
					password));
			store.store(outStream, password);
			outStream.close();
		} catch (Exception e) {
			e.printStackTrace();

		}
	}

	public Enumeration<String> getAliases() throws KeyStoreException {
		return store.aliases();
	}
	
}
