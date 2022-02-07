package com.polytech.security;

import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import java.util.*;

public class TripleDES{

	static public void main(String[] argv){
		
		Provider prov = new org.bouncycastle.jce.provider.BouncyCastleProvider();
		Security.addProvider(prov);
		
		try{
	
			if(argv.length>0){
			
				// Create a TripleDES object 
				TripleDES the3DES = new TripleDES();
			
				if(argv[0].compareTo("-ECB")==0){
					// ECB mode
				  	// encrypt ECB mode
				  	Vector Parameters= 
					  	the3DES.encryptECB(
					  			new FileInputStream(new File(argv[1])),  	// clear text file 
				   	  			new FileOutputStream(new File(argv[2])), 	// file encrypted
				   	  			"DES", 										// KeyGeneratorName
				   	  			"DES/ECB/NoPadding"); 						// CipherName 
				  	// decrypt ECB mode
				  	the3DES.decryptECB(Parameters,				 			// the 3 DES keys
				  				new FileInputStream(new File(argv[2])),  	// the encrypted file 
				   	  			new FileOutputStream(new File(argv[3])),	// the decrypted file
				   	  			"DES/ECB/NoPadding"); 		  				// CipherName
				}	
				else if(argv[0].compareTo("-CBC")==0){
					// decryption
				  	// encrypt CBC mode
				  	Vector Parameters = 
					  	the3DES.encryptCBC(
					  			new FileInputStream(new File(argv[1])),  	// clear text file 
				   	  			new FileOutputStream(new File(argv[2])), 	// file encrypted
				   	  			"DES", 										// KeyGeneratorName
					  			"DES/CBC/NoPadding"); 						// CipherName
				   	  			//"DES/CBC/PKCS5Padding"); 					// CipherName 
				  	// decrypt CBC mode	
				  	the3DES.decryptCBC(
				  				Parameters,				 					// the 3 DES keys
			  					new FileInputStream(new File(argv[2])),  	// the encrypted file 
			  					new FileOutputStream(new File(argv[3])),	// the decrypted file
				  				"DES/CBC/NoPadding"); 						// CipherName			
				  				//"DES/CBC/PKCS5Padding"); 		  			// CipherName	  
				}
			
			}
			
			else{
				System.out.println("java TripleDES -ECB clearTextFile EncryptedFile DecryptedFile");
				System.out.println("java TripleDES -CBC clearTextFile EncryptedFile DecryptedFile");
			} 
		}catch(Exception e){
			e.printStackTrace();
			System.out.println("java TripleDES -ECB clearTextFile EncryptedFile DecryptedFile");
			System.out.println("java TripleDES -CBC clearTextFile EncryptedFile DecryptedFile");
		}
	}

	
	/**
	 * 3DES ECB Encryption
	 */
	private Vector encryptECB(FileInputStream in, 
							FileOutputStream out, 
							String KeyGeneratorInstanceName, 
							String CipherInstanceName){
		try{
		
			// GENERATE 3 DES KEYS
			KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyGeneratorInstanceName);
			keyGenerator.init(56);
			SecretKey keys1 = keyGenerator.generateKey();
			SecretKey keys2 = keyGenerator.generateKey();
			SecretKey keys3 = keyGenerator.generateKey();
		
			// CREATE A DES CIPHER OBJECT 
			// WITH CipherInstanceName
			// FOR ENCRYPTION
			// WITH THE FIRST GENERATED DES KEY

			Cipher cipher = Cipher.getInstance(CipherInstanceName);
			// GET THE MESSAGE TO BE ENCRYPTED FROM IN
			for ( byte[] msg = in.readNBytes(112); in.available() > 0; msg = in.readNBytes(112) ) {
				// CIPHERING
				// CIPHER WITH THE FIRST KEY
				// DECIPHER WITH THE SECOND KEY
				// CIPHER WITH THE THIRD KEY
				// write encrypted file
				cipher.init(Cipher.ENCRYPT_MODE, keys1);
				byte[] msg1 = cipher.doFinal(msg);

				// CREATE A DES CIPHER OBJECT
				// WITH CipherInstanceName
				// FOR DECRYPTION
				// WITH THE SECOND GENERATED DES KEY
				cipher.init(Cipher.DECRYPT_MODE, keys2);
				byte[] msg2 = cipher.doFinal(msg1);

				// CREATE A DES CIPHER OBJECT
				// WITH CipherInstanceName
				// FOR ENCRYPTION
				// WITH THE THIRD GENERATED DES KEY
				cipher.init(Cipher.ENCRYPT_MODE, keys3);
				byte[] encrypted = cipher.doFinal(msg2);

				// WRITE THE ENCRYPTED DATA IN OUT
				out.write(encrypted);
			}
			in.close();
			out.close();
			Vector<SecretKey> vector = new Vector<SecretKey>();
			vector.add(keys1);
			vector.add(keys2);
			vector.add(keys3);

			// return the DES keys list generated
			return vector;

		}catch(Exception e){
			e.printStackTrace();
			return null;
		}
		
	}
	
	/**
	 * 3DES ECB Decryption 
	 */
	private void decryptECB(Vector Parameters, 
						FileInputStream in, 
						FileOutputStream out, 
						String CipherInstanceName){
		try{
			SecretKey keys1 = (SecretKey) Parameters.elementAt(0);
			SecretKey keys2 = (SecretKey) Parameters.elementAt(1);
			SecretKey keys3 = (SecretKey) Parameters.elementAt(2);

			Cipher cipher = Cipher.getInstance(CipherInstanceName);

			// GET THE ENCRYPTED DATA FROM IN
			for ( byte[] text = in.readNBytes(112); in.available() > 0 ; text = in.readNBytes(112) ) {
				// CREATE A DES CIPHER OBJECT
				// WITH CipherInstanceName
				// FOR DECRYPTION
				// WITH THE THIRD GENERATED DES KEY
				cipher.init(Cipher.DECRYPT_MODE, keys3);
				byte[] msg1 = cipher.update(text);
				// CREATE A DES CIPHER OBJECT
				// WITH CipherInstanceName
				// FOR ENCRYPTION
				// WITH THE SECOND GENERATED DES KEY
				cipher.init(Cipher.ENCRYPT_MODE, keys2);
				byte[] msg2 = cipher.update(msg1);
				// CREATE A DES CIPHER OBJECT FOR ENCRYPTION
				// WITH CipherInstanceName
				// FOR DECRYPTION
				// WITH THE FIRST GENERATED DES KEY
				cipher.init(Cipher.DECRYPT_MODE, keys1);
				byte[] decrypted = cipher.doFinal(msg2);

				// WRITE THE DECRYPTED DATA IN OUT
				out.write(decrypted);
				if (in.available() <= 0 ) {
					break;
				}
			}

			in.close();
			out.close();
			
		}catch(Exception e){
			e.printStackTrace();
		}

	}
	  
	/**
	 * 3DES CBC Encryption
	 */
	private Vector encryptCBC(FileInputStream in, 
							FileOutputStream out, 
							String KeyGeneratorInstanceName, 
							String CipherInstanceName){
		try{
			// GENERATE 3 DES KEYS
			KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyGeneratorInstanceName);
			keyGenerator.init(56);
			SecretKey keys1 = keyGenerator.generateKey();
			SecretKey keys2 = keyGenerator.generateKey();
			SecretKey keys3 = keyGenerator.generateKey();

			Cipher cipher = Cipher.getInstance(CipherInstanceName);
			// GENERATE THE IV
			byte[] ivBytes = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 };

			// GET THE DATA TO BE ENCRYPTED FROM IN
			for ( byte[] msg = in.readNBytes(112); in.available() > 0 ; msg = in.readNBytes(112) ) {
				// CREATE A DES CIPHER OBJECT
				// WITH CipherInstanceName
				// FOR ENCRYPTION
				// WITH THE FIRST GENERATED DES KEY
				cipher.init(Cipher.ENCRYPT_MODE, keys1, new IvParameterSpec(ivBytes));
				byte[] msg1 = cipher.update(msg);

				// CREATE A DES CIPHER OBJECT
				// WITH CipherInstanceName
				// FOR DECRYPTION
				// WITH THE SECOND GENERATED DES KEY
				cipher.init(Cipher.DECRYPT_MODE, keys2, new IvParameterSpec(cipher.getIV()));
				byte[] msg2 = cipher.update(msg1);

				// CREATE A DES CIPHER OBJECT
				// WITH CipherInstanceName
				// FOR ENCRYPTION
				// WITH THE THIRD GENERATED DES KEY
				cipher.init(Cipher.ENCRYPT_MODE, keys3, new IvParameterSpec(cipher.getIV()));
				byte[] encrypted = cipher.doFinal(msg2);

				// WRITE THE ENCRYPTED DATA IN OUT
				out.write(encrypted);
				if (in.available() <= 0) {
					break;
				}
			}
			in.close();
			out.close();
			Vector<SecretKey> vector = new Vector<SecretKey>();
			vector.add(keys1);
			vector.add(keys2);
			vector.add(keys3);

			// return the DES keys list generated
			return vector;
			
		}catch(Exception e){
			e.printStackTrace();
			return null;
		}
	}
	
	/**
	 * 3DES CBC Decryption 
	 */
	private void decryptCBC(Vector Parameters, 
						FileInputStream in, 
						FileOutputStream out, 
						String CipherInstanceName){
		try{
			SecretKey keys1 = (SecretKey) Parameters.elementAt(0);
			SecretKey keys2 = (SecretKey) Parameters.elementAt(1);
			SecretKey keys3 = (SecretKey) Parameters.elementAt(2);

			Cipher cipher = Cipher.getInstance(CipherInstanceName);
			byte[] ivBytes = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 };

			for ( byte[] text = in.readNBytes(112); true ; text = in.readNBytes(112) ) {
				// CREATE A DES CIPHER OBJECT
				// WITH CipherInstanceName
				// FOR DECRYPTION
				// WITH THE THIRD GENERATED DES KEY
				cipher.init(Cipher.DECRYPT_MODE, keys3, new IvParameterSpec(ivBytes));
				byte[] msg1 = cipher.update(text);

				// CREATE A DES CIPHER OBJECT
				// WITH CipherInstanceName
				// FOR ENCRYPTION
				// WITH THE SECOND GENERATED DES KEY
				cipher.init(Cipher.ENCRYPT_MODE, keys2, new IvParameterSpec(cipher.getIV()));
				byte[] msg2 = cipher.update(msg1);

				// CREATE A DES CIPHER OBJECT FOR ENCRYPTION
				// WITH CipherInstanceName
				// FOR DECRYPTION
				// WITH THE FIRST GENERATED DES KEY
				cipher.init(Cipher.DECRYPT_MODE, keys1, new IvParameterSpec(cipher.getIV()));
				byte[] decrypted = cipher.doFinal(msg2);

				// WRITE THE DECRYPTED DATA IN OUT
				out.write(decrypted);
				if (in.available() <= 0 ) {
					break;
				}
			}
			in.close();
			out.close();
			
		}catch(Exception e){
			e.printStackTrace();
		}

	}
	  

}