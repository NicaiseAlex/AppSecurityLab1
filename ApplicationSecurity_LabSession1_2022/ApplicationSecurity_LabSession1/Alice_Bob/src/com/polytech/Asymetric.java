package com.polytech;

/**
* TD2 - RSA signature, encryption/decryption
*
* asymetric clearTextFile SignatureFile CipheredFile DecipheredFile
**/

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.io.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class Asymetric{

	static public void main(String argv[]){

		// INITIALIZATION
		
		// load the bouncycastle provider
		//Provider prov = new org.bouncycastle.jce.provider.BouncyCastleProvider();
		//Security.addProvider(prov);

		// create two new entity
		Entity Alice = new Entity();
		Entity Bob = new Entity();
		
		try{
		
			// GET THE CLEAR TEXT
			File aFile = new File(argv[0]);
			FileInputStream in = new FileInputStream(aFile);
			byte[] aMessage = new byte[(int)aFile.length()];
			in.read(aMessage);
			in.close();
			
			// RSA SIGNATURE
			System.out.println("\nRSA SIGNATURE\n");
				// MAKE ALICE SIGN IT
					// display the clear text
					System.out.println("Message == \n"+new String(aMessage));
					// sign it
					byte[] aSignature = Alice.sign(aMessage);
					// display and store the signature
					System.out.println("Alice Signature == \n"+new String(aSignature));
					FileOutputStream out = new FileOutputStream(new File(argv[1]));
					out.write(aSignature);
					out.close();
			
				// BOB CHECKS THE ALICE SIGNATURE
				System.out.println("Bob signature verification == \n"+Bob.checkSignature(aMessage, aSignature, Alice.thePublicKey));
				
			// MY RSA SIGNATURE
			System.out.println("\nMY RSA SIGNATURE\n");
				// MAKE ALICE SIGN IT
					// display the clear text
					System.out.println("Message == \n"+new String(aMessage));
					// sign it
					aSignature = Alice.mySign(aMessage);
					// display and store the signature
					System.out.println("Alice Signature == \n"+new String(aSignature));
					out = new FileOutputStream(new File(argv[1]));
					out.write(aSignature);
					out.close();
			
				// BOB CHECKS THE ALICE SIGNATURE
				System.out.println("Bob signature verification == "+Bob.myCheckSignature(aMessage, aSignature, Alice.thePublicKey));
	
			// RSA ENCRYPTION/DECRYPTION
			System.out.println("\nRSA ENCRYPTION\n");
				// bob encrypt a message with the alice public key
				System.out.println("Clear Text == \n"+new String(aMessage));
				byte[] aCiphered = Bob.encrypt(aMessage, Alice.thePublicKey);
				System.out.println("Ciphered Text== \n"+new String(aCiphered)+"\n");
				out = new FileOutputStream(new File(argv[2]));
				out.write(aCiphered);
				out.close();
				
				// alice decrypt the message
				byte[] aDeciphered = Alice.decrypt(aCiphered);
				System.out.println("Deciphered Text== \n"+new String(aDeciphered));
				out = new FileOutputStream(new File(argv[3]));
				out.write(aDeciphered);
				out.close();

			// PROTOCOL IMPLEMENTATION
				KeyExchangeProtocol();
		}catch(Exception e){
			e.printStackTrace();
			System.out.println("java Asymetric clearTextFile SignatureFile CipheredFile DecipheredFile");
		}
	}

	private static void KeyExchangeProtocol() throws NoSuchAlgorithmException, InvalidKeySpecException {
		Entity Alice, Bob;

		Alice = new Entity();
		Bob = new Entity();

		//	Alice sends her public key to Bob.
		// On sait que bob peut recevoir la public key de Alice on pourra donc utiliser Alice.thePublicKey dans les fonctions de bob.

		//	Bob generate a DES session key.
		KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
		keyGenerator.init(56);
		SecretKey key = keyGenerator.generateKey();

		System.out.println("Bob créé sa session key : " + Arrays.toString(key.getEncoded()));

		//	Bob encrypts it with Alice’s public key. Alice.thePublicKey pourrait etre une variable que possède bob.
		byte[] sessionKeyEnc = Bob.encrypt(key.getEncoded(), Alice.thePublicKey);

		//	Alice decrypts the DES key with her private key.
		byte[] sessionKeyDec = Alice.decrypt(sessionKeyEnc);
		SecretKeySpec keyDecSpec = new SecretKeySpec(sessionKeyDec, "DES");
		SecretKeyFactory keyDecFactkey = SecretKeyFactory.getInstance("DES");
		SecretKey keyDec = keyDecFactkey.generateSecret(keyDecSpec);

		System.out.println("Alice décrypte la session key de bob : " + Arrays.toString(keyDec.getEncoded()));

		//  Alice sends a message to Bob with her session key
		byte[] msgEncrypt = Alice.encryptDES("Test".getBytes(), keyDec);
		System.out.println("Alice créé un message pour bob et l'encypte : " + Arrays.toString(msgEncrypt));

		//	Bob decrypts the message with the session key.
		byte[] msgDecrypt = Bob.decryptDES(msgEncrypt, key);
		System.out.println("bob recois le message et le decrypte : " + Arrays.toString(msgDecrypt));
	}
}