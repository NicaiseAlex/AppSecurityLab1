package com.polytech;


import java.security.*;
import javax.crypto.*;

import java.io.*;

public class Entity{

	// keypair
	public PublicKey thePublicKey;
	private PrivateKey thePrivateKey;
	
	/**
	  * Entity Constructor
	  * Public / Private Key generation
	 **/
	public Entity(){
		// INITIALIZATION

		// generate a public/private key
		try{
			// get an instance of KeyPairGenerator  for RSA
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			// Initialize the key pair generator for 1024 length
			keyPairGenerator.initialize(1024);
			// Generate the key pair
			KeyPair pair = keyPairGenerator.generateKeyPair();

			// save the public/private key
			this.thePublicKey = pair.getPublic();
			this.thePrivateKey = pair.getPrivate();
		}catch(Exception e){
			System.out.println("Signature error");
			e.printStackTrace();
		}
	}

	/**
	  * Sign a message
	  * Parameters
	  * aMessage : byte[] to be signed
	  * Result : signature in byte[] 
	  **/
	public byte[] sign(byte[] aMessage){
		
		try{
			// use of java.security.Signature
			// Init the signature with the private key
			Signature signature = Signature.getInstance("SHA1withRSA");
			signature.initSign(thePrivateKey);

			// update the message
			signature.update(aMessage);
			// sign
			return signature.sign();
		}catch(Exception e){
			System.out.println("Signature error");
			e.printStackTrace();
			return null;
		}
		
	}
	
	/**
	  * Check aSignature is the signature of aMessage with aPK
	  * Parameters
	  * aMessage : byte[] to be signed
	  * aSignature : byte[] associated to the signature
	  * aPK : a public key used for the message signature
	  * Result : signature true or false
	  **/
	public boolean checkSignature(byte[] aMessage, byte[] aSignature, PublicKey aPK){
		try{
			// use of java.security.Signature
			// init the signature verification with the public key
			Signature signature = Signature.getInstance("SHA1withRSA");
			signature.initVerify(aPK);

			// update the message
			signature.update(aMessage);
			// check the signature
			return signature.verify(aSignature);
		}catch(Exception e){
			System.out.println("Verify signature error");
			e.printStackTrace();
			return false;
		}
	}
	
	
	/**
	  * Sign a message
	  * Parameters
	  * aMessage : byte[] to be signed
	  * Result : signature in byte[] 
	  **/
	public byte[] mySign(byte[] aMessage){
		
		try{
			// get an instance of a cipher with RSA with ENCRYPT_MODE
			// Init the signature with the Public key
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, thePrivateKey);
			byte[] msg = cipher.update(aMessage);

			// get an instance of the java.security.MessageDigest with SHA1
			// process the digest
			MessageDigest messageDigest = MessageDigest.getInstance("SHA1");

			// return the encrypted digest
			return messageDigest.digest(msg);
		}catch(Exception e){
			System.out.println("Signature error");
			e.printStackTrace();
			return null;
		}
		
	}
	
	/**
	  * Check aSignature is the signature of aMessage with aPK
	  * Parameters
	  * aMessage : byte[] to be signed
	  * aSignature : byte[] associated to the signature
	  * aPK : a public key used for the message signature
	  * Result : signature true or false
	  **/
	public boolean myCheckSignature(byte[] aMessage, byte[] aSignature, PublicKey aPK){
		try{
			// get an instance of a cipher with RSA with ENCRYPT_MODE
			// Init the signature with the private key
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, aPK);
			// decrypt the signature
			byte[] msg = cipher.update(aSignature);
			// get an instance of the java.security.MessageDigest with SHA1
			MessageDigest messageDigest = MessageDigest.getInstance("SHA1");

			// process the digest
			byte[] msg2 = messageDigest.digest(aMessage);
			
			// check if digest1 == digest2
			return msg == msg2;

		}catch(Exception e){
			System.out.println("Verify signature error");
			e.printStackTrace();
			return false;
		}
	}	
	
	
	/**
	  * Encrypt aMessage with aPK
	  * Parameters
	  * aMessage : byte[] to be encrypted
	  * aPK : a public key used for the message encryption
	  * Result : byte[] ciphered message
	  **/
	public byte[] encrypt(byte[] aMessage, PublicKey aPK){
		try{
			// get an instance of RSA Cipher
			Cipher cipher = Cipher.getInstance("RSA");

			// init the Cipher in ENCRYPT_MODE and aPK
			cipher.init(Cipher.ENCRYPT_MODE, aPK);

			// use doFinal on the byte[] and return the ciphered byte[]
			return cipher.doFinal(aMessage);
		}catch(Exception e){
			System.out.println("Encryption error");
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Encrypt aMessage with aPK
	 * Parameters
	 * aMessage : byte[] to be encrypted
	 * aPK : a public key used for the message encryption
	 * Result : byte[] ciphered message
	 **/
	public byte[] encryptDES(byte[] aMessage, SecretKey sessionKey){
		try{
			// get an instance of RSA Cipher
			Cipher cipher = Cipher.getInstance("DES");

			// init the Cipher in ENCRYPT_MODE and aPK
			cipher.init(Cipher.ENCRYPT_MODE, sessionKey);

			// use doFinal on the byte[] and return the ciphered byte[]
			return cipher.doFinal(aMessage);
		}catch(Exception e){
			System.out.println("Encryption error");
			e.printStackTrace();
			return null;
		}
	}

	/**
	  * Decrypt aMessage with the entity private key
	  * Parameters
	  * aMessage : byte[] to be encrypted
	  * Result : byte[] deciphered message
	  **/
	public byte[] decrypt(byte[] aMessage){
		try{
			// get an instance of RSA Cipher
			Cipher cipher = Cipher.getInstance("RSA");

			// init the Cipher in DECRYPT_MODE and Session key
			cipher.init(Cipher.DECRYPT_MODE, this.thePrivateKey);

			// use doFinal on the byte[] and return the deciphered byte[]
			return cipher.doFinal(aMessage);
			
		}catch(Exception e){
			System.out.println("Encryption error");
			e.printStackTrace();
			return null;
		}

	}

	/**
	 * Decrypt aMessage with the entity private key
	 * Parameters
	 * aMessage : byte[] to be encrypted
	 * Result : byte[] deciphered message
	 **/
	public byte[] decryptDES(byte[] aMessage, SecretKey sessionKey){
		try{
			// get an instance of RSA Cipher
			Cipher cipher = Cipher.getInstance("DES");

			// init the Cipher in DECRYPT_MODE and Session key
			cipher.init(Cipher.DECRYPT_MODE, sessionKey);

			// use doFinal on the byte[] and return the deciphered byte[]
			return cipher.doFinal(aMessage);

		}catch(Exception e){
			System.out.println("Encryption error");
			e.printStackTrace();
			return null;
		}

	}


}