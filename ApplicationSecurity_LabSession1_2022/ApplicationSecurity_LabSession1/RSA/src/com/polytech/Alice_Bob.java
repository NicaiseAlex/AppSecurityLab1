package com.polytech;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class Alice_Bob {

    static public void main(String argv[]) throws NoSuchAlgorithmException, InvalidKeySpecException {
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
        String msg = "Test Alice to Bob";
        byte[] msgEncrypt = Alice.encryptDES(msg.getBytes(), keyDec);
        System.out.println("Alice créé un message pour bob : " + msg);

        //	Bob decrypts the message with the session key.
        byte[] msgDecrypt = Bob.decryptDES(msgEncrypt, key);
        String test = new String(msgDecrypt);
        System.out.println("bob recois le message et le decrypte : " + test);
    }
}
