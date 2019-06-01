/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package network.serverclient_exchange;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import static java.lang.Thread.sleep;

import java.beans.PropertyDescriptor;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.util.Date;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import java.io.BufferedOutputStream;

import java.io.FileOutputStream;

import java.io.ObjectOutputStream;

import java.math.BigInteger;

import java.security.InvalidAlgorithmParameterException;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Timestamp;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.sql.Timestamp;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import sun.security.util.*; 
import sun.security.x509.X509Key;
import org.json.simple.parser.JSONParser;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class ServerTCP extends ServerSocket {

	private final ServerSocket serverSocket;
	private Socket client;
	private InputStream is;
	private InputStreamReader isr;
	private BufferedReader br;
	private SecretKeySpec clientkey;
	private final SecretKey serversharedkey;
	private OutputStream os;
	private OutputStreamWriter osw;
	private final KeyGenerator keyGenerator;
	private PrintWriter pw;
	private final Scanner input;

	BufferedWriter out;
	BufferedReader in;
	
    private static PublicKey publicKey;
    private static String encodedKey;
    JSONParser parser = new JSONParser();


	/**
	 * initialize the server: initialize the serverSocket, Input, keyGenerator
	 * Generate the server encryption key with the AES algo / export the key into a
	 * serversharedKey txt file
	 * @throws InvalidKeySpecException 
	 * 
	 *
	 **/

	public ServerTCP(int port) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException, InvalidKeySpecException {
		this.serverSocket = new ServerSocket(port);
		input = new Scanner(new InputStreamReader(System.in));
		keyGenerator = KeyGenerator.getInstance("AES");
		serversharedkey = keyGenerator.generateKey();
		
		GetTimestamp("Creating sharedkey: " ) ;
		
		encodedKey = exportkey();
		
		GetTimestamp("Sharedkey is created: " ) ;
		
		
		
	}


	/**
	 * listen on the port and wait for a client serverSocket.accept () initialize
	 * Input / Output StreamWriter, PrintWriter, BufferedReader generate the key of
	 * the client with the algo AES / export the key in a file txt clientKey import
	 * the client key from clientKey file put the server on hold to receive a
	 * message
	 * @throws Exception 
	 *
	 **/

	public void getConnection() throws Exception {
		try {
			System.out.println("Waiting for new client!");



			client = serverSocket.accept();
			is = client.getInputStream();
			isr = new InputStreamReader(is);
			br = new BufferedReader(isr);
			os = client.getOutputStream();
			osw = new OutputStreamWriter(os);
			pw = new PrintWriter(osw, true);
			sleep(500);
			//clientkey = getClientKey();
			System.out.println("Client has connected!");
			
			GetTimestamp("Client Publickey is being stored: " ) ;
			
			publicKey = getClientPublicKey();
			
			GetTimestamp("Client Publickey is stored: " ) ;
			
			String tosend = encrypt1(getSharedKey(), getClientPublicKey());
			
			GetTimestamp("Client sharedkey is being encrypted: ") ;
			
			GetTimestamp("Waiting for Authorization Request from Client: ");
			
			//getclientpublickey();
			getAUTH_REQUEST();
			//getMessage();

		} catch (IOException | InterruptedException ex) {
			Logger.getLogger(ServerTCP.class.getName()).log(Level.SEVERE, null, ex);
		}
	}

	/**
	 * method allowing the server to complete the connection close the buffer, input
	 * / output put the server on hold to receive a message
	 * @throws Exception 
	 *
	 **/
	public void closeConnection() throws Exception {
		try {
			client.close();
			is.close();
			isr.close();
			br.close();
			System.out.println("Connection is closed");
			getConnection();
		} catch (IOException ex) {
			Logger.getLogger(ServerTCP.class.getName()).log(Level.SEVERE, null, ex);
		}

	}
	
	private void sendMessage1() throws Exception {
		GetTimestamp("Sending Message Encrypted with Client's PubK: ");
		String inputMessage;
		inputMessage = input.nextLine();
		

		String tosend = encrypt(clientkey, inputMessage);
		
		
		JSONObject RESPONSE = new JSONObject();
		RESPONSE.put("payload",tosend);
		
		GetTimestamp("Sending Message Encrypted with Client's PubK: + RESPONSE");
		
		pw.println(tosend);
		pw.flush();
		System.out.println("Message sent to the client : " + inputMessage);
		if (inputMessage.equalsIgnoreCase("bye")) {
			System.out.println("sending close command");
			closeConnection();
		} else {
			getCommand();
		}
	}	

	/**
	 * method that allows the server to send messages to the client encrypt the
	 * message with the client's key Then the server waits for the customer to
	 * respond
	 * @throws Exception 
	 *
	 **/

	private void sendMessage() throws Exception {
		GetTimestamp("Sending Message: ");
		String inputMessage;
		inputMessage = input.nextLine();
		String tosend = encrypt(clientkey, inputMessage);
		
		JSONObject RESPONSE = new JSONObject();
		RESPONSE.put("payload",tosend);
		System.out.println(RESPONSE);
		
		pw.println(tosend);
		pw.flush();
		System.out.println("Message sent to the client : " + inputMessage);
		if (inputMessage.equalsIgnoreCase("bye")) {
			System.out.println("sending close command");
			closeConnection();
		} else {
			getMessage();
		}
	}

	/**
	 * method allowing the server to receive messages from the client decrypt the
	 * message with the server key then the server will send its reposne to the
	 * client
	 * @throws Exception 
	 *
	 **/

	private void getMessage() throws Exception {
		GetTimestamp("Getting Message: ");
		String msg = "";
		String decmsg = "";
		byte[] result;
		try {
			msg = br.readLine();
			JSONObject RESPONSE = new JSONObject();
			RESPONSE.put("payload", msg);
			System.out.println(RESPONSE);
			decmsg = decrypt(serversharedkey, msg);
			System.out.println("Decrypted Message from client is " + decmsg);

		} catch (IOException ex) {
			Logger.getLogger(ServerTCP.class.getName()).log(Level.SEVERE, null, ex);
		}
		if (decmsg.equalsIgnoreCase("bye")) {
			System.out.println("Client has signed out!");
			closeConnection();

		} else {
			sendMessage();
		}

	}
	
	private void getCommand() throws Exception {
		
		
		String msg = "";
		String decmsg = "";
		byte[] result;
		try {
			msg = br.readLine();
			JSONObject REQUEST = new JSONObject();
			REQUEST.put("payload", msg);
			GetTimestamp("Getting Command: " + REQUEST);
			
			decmsg = decrypt(serversharedkey, msg);
			GetTimestamp("Decrepted Command " + decmsg);
			
	    	switch(decmsg) {
	    	
    		case "LIST_PEERS_REQUEST": 
    			
    			
    			String tosend = encrypt(getSharedKey(), server.getpeers);
    	        
    			JSONObject RESPONSE = new JSONObject();
    			RESPONSE.put("payload", tosend);
    			
    	        
    	        pw.println(tosend);
    	        pw.flush();
    	        GetTimestamp("Sending LIST PEERS REQUEST Command: ");
    	        
    			
    	        getCommand();
    	        
    			break;
    			
    		case "CONNECT_PEER_REQUEST": 
    			
    			
    			String tosend2 = encrypt(getSharedKey(), server.getpeers);
    	        
    			JSONObject RESPONSE2 = new JSONObject();
    			RESPONSE.put("payload", tosend);
    			
    	        
    	        pw.println(tosend);
    	        pw.flush();
    	        GetTimestamp("Sending LIST PEERS REQUEST Command: ");
    	        
    			
    	        getCommand();
    	        
    			break;
    		case "DISCONNECT_PEER_REQUEST": 
    			
    			
    			String tosend3 = encrypt(getSharedKey(), server3.getpeers);
    	        
    			JSONObject RESPONSE3 = new JSONObject();
    			RESPONSE.put("payload", tosend);
    			
    	        
    	        pw.println(tosend);
    	        pw.flush();
    	        GetTimestamp("Sending LIST PEERS REQUEST Command: ");
    	        
    			
    	        getCommand();
	    	}
    	        
    			break;
	    	} catch (IOException ex) {
				Logger.getLogger(ServerTCP.class.getName()).log(Level.SEVERE, null, ex);
			}
	    	
		if (decmsg.equalsIgnoreCase("bye")) {
			System.out.println("Client has signed out!");
			closeConnection();

		} else {
			sendMessage();
		}

	}

	/**
	 * method allowing the server to receive AUTH_REQUEST() from the client then the server will send its response to the
	 * client
	 * @throws Exception 
	 *
	 **/
	private void getAUTH_REQUEST() throws Exception {
		
		boolean status = true;
		boolean status2 = false;
		String msg = "";
		
		//File filePK = new File("identity");
	
		try {
			
			msg = br.readLine();
			GetTimestamp("Received Authorization Request from Client: " + msg);
			
			JSONObject REQUEST = (JSONObject) parser.parse(msg);
	        String identity = REQUEST.get("identity").toString();
			
			
	        if((identity.contains("aaron@krusty"))) {

	        	GetTimestamp("Authorization Request from Client is approved: ");

	        	GetTimestamp("Client Publickey is stored: " ) ;

	        	String tosend = encrypt1(getSharedKey(), getClientPublicKey());

	        	GetTimestamp("Server sharedkey is being encrypted with Client's publickey to be sent: ") ;

	        	JSONObject RESPONSE = new JSONObject();
	        	RESPONSE.put("command","AUTH_RESPONSE");
	        	RESPONSE.put("AES128", tosend);
	        	RESPONSE.put("status", status);
	        	RESPONSE.put("message", "public key found");

	        	StringWriter out = new StringWriter();
	        	RESPONSE.writeJSONString(out);

	        	String AUTH_RESPONSE = out.toString();
	        	System.out.println(AUTH_RESPONSE);

	        	GetTimestamp("Sending Authorization Response to Client: ");

	        	pw.println(AUTH_RESPONSE);
	        	pw.flush();



	        }
	        else {

	        	System.out.println("Client " + REQUEST.get("identity") + " has been rejected");

	        	JSONObject RESPONSE = new JSONObject();
	        	RESPONSE.put("command","AUTH_RESPONSE");
	        	RESPONSE.put("status", status2);
	        	RESPONSE.put("message", "public key not found");

	        	StringWriter out = new StringWriter();
	        	RESPONSE.writeJSONString(out);

	        	String AUTH_RESPONSE = out.toString();
	        	System.out.println(AUTH_RESPONSE);

	        	pw.println(AUTH_RESPONSE);
	        	pw.flush();

	        	closeConnection();
	        }
				
			
		} catch (IOException ex) {
			Logger.getLogger(ServerTCP.class.getName()).log(Level.SEVERE, null, ex);
		}
		if (msg.equalsIgnoreCase("bye")) {
			System.out.println("Client has signed out!");
			closeConnection();

		} else {	
			getMessage();
		}
	}

	/**
	 * method allowing the server to encrypt (asymmetric) the messages to be sent an
	 * average to improve the security of these exchanges is to add to the message a
	 * random vector so as not to know what to enter before "XOR" encryption
	 **/

	private String encrypt(SecretKey key, String value) {
		try {

			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, key);

			byte[] encrypted = cipher.doFinal(value.getBytes());
			return Base64.encodeBase64String(encrypted);
		} catch (InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException
				| NoSuchPaddingException ex) {
			System.out.println(ex.getMessage());
		}

		return null;
	}
	
	private  String encrypt1(SecretKey skey, PublicKey pkey){
        
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, pkey);
            byte[] encrypted = cipher.doFinal(skey.getEncoded());
            return Base64.encodeBase64String(encrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
	

	/**
	 * method allowing the server to decrypt the messages it receives the client
	 * with the server key
	 **/

	private String decrypt(SecretKey key, String encrypted) {
		try {
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.DECRYPT_MODE, key);

			byte[] original = cipher.doFinal(Base64.decodeBase64(encrypted));

			return new String(original);
		} catch (InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException
				| NoSuchPaddingException ex) {
			System.out.println(ex.getMessage());
		}

		return null;
	}

	/**
	 * method allowing the server to export sharedkey in a txt file
	 *
	 **/
	private String exportkey() {

		try {
			byte[] keyBytes = serversharedkey.getEncoded();
			String encodedKey = new String(Base64.encodeBase64(keyBytes), "UTF-8");
			File file = new File("serversharedKey");
			//System.out.println("The server Private key: " + encodedKey);
			PrintWriter writer = new PrintWriter(file, "UTF-8");
			writer.println(encodedKey);
			writer.close();

			return encodedKey;

		} catch (UnsupportedEncodingException | FileNotFoundException ex) {
			Logger.getLogger(ClientTCP.class.getName()).log(Level.SEVERE, null, ex);
		}
		return null;
	}
	
	private SecretKeySpec getSharedKey() {
		BufferedReader brf;
		SecretKeySpec key = null;
		try {
			brf = new BufferedReader(new FileReader("serversharedkey"));
			String code = brf.readLine();
			brf.close();
			//System.out.println("Server importing client encription key from clientKey: " + code);
			byte[] keyBytes = Base64.decodeBase64(code.getBytes("UTF-8"));
			key = new SecretKeySpec(keyBytes, "AES");
			
			
		} catch (FileNotFoundException ex) {
			Logger.getLogger(ServerTCP.class.getName()).log(Level.SEVERE, null, ex);
		} catch (IOException ex) {
			Logger.getLogger(ServerTCP.class.getName()).log(Level.SEVERE, null, ex);
		}
		return key;
	}
	
	  /**
     * method that allows the server to import the client encryption key from a txt
     * file "clientKey"
     **/
	
//	private SecretKeySpec getClientPublicKey1() {
//		BufferedReader brf;
//		PublicKey key = null;
//		try {
//			brf = new BufferedReader(new FileReader("clientPublicKey"));
//			String code = brf.readLine();
//			brf.close();
//			//System.out.println("Server importing client encription key from clientKey: " + code);
//			
//			//Need to be from the configuration
//			GetTimestamp("Storing client's Publickey: code hi yassin" + code);
//			
//			
//			//byte[] keyBytes = publicKey.getEncoded();
//            //String encodedKey = new String(Base64.encodeBase64(keyBytes), "UTF-8");
//			//byte[] keyBytes = Files.readAllBytes(new File(clientPublicKey).toPath());
//			
//			byte[] keyBytes = Base64.encodeBase64(code.getBytes("UTF-8"));
//			GetTimestamp("Storing client's Publickey: code hi yassin" + code);
//			//key = new SecretKeySpec(keyBytes, "RSA");
//			
//			//GetTimestamp("Storing client's Publickey: " + key);
//			
//			//key = new SecretKeySpec(keyBytes, "AES");
//			
//			GetTimestamp("Client's Publickey is stored: " + key);
//			
//		} catch (FileNotFoundException ex) {
//			Logger.getLogger(ServerTCP.class.getName()).log(Level.SEVERE, null, ex);
//		} catch (IOException ex) {
//			Logger.getLogger(ServerTCP.class.getName()).log(Level.SEVERE, null, ex);
//		}
//		return key;
//	}
	
	

	private PublicKey getClientPublicKey() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {

		String path = "readclientPublicKey";

	    //Generate a keypair to write to file
	    //KeyPair kp = generate_key();
	    //PublicKey pub_key = kp.getPublic();
	    //File file = new File(path);
	    
	    //byte[] keyBytes = pub_key.getEncoded();
	    //String encodedKey = new String(Base64.encodeBase64(keyBytes), "UTF-8");
		
	    //GetTimestamp("Check0: " + encodedKey);
	    
		PublicKey public_key = null;
		try {
			
			// Write to file
	        //file.createNewFile();
	        //FileOutputStream out = new FileOutputStream(path);

	        //out.write(pub_key.getEncoded()); // Write public key to the file
	        //out.close();
			
			
			// Read from file
	        FileInputStream in = new FileInputStream(path);
	        byte[] pub_key_arr = new byte[in.available()];
	        //GetTimestamp("Check1: " + pub_key_arr);
	        in.read(pub_key_arr, 0, in.available());
	        in.close();

	        // Reconstruct public key
	        PublicKey reconstructed_pub_key = reconstruct_public_key("RSA", pub_key_arr);
	        
	        public_key = reconstructed_pub_key;
	        
	        
	        //GetTimestamp("Check2: " + public_key);
	        
	        //byte[] encryptedData = encrypt(publicKey,
	                //"hi this is Visruth here".getBytes());
	        
//	        keyPairGenerator.initialize(2048);
//            keyPair = keyPairGenerator.generateKeyPair();
//            privateKey =  keyPair.getPrivate();
//            publicKey = keyPair.getPublic();
//        	
//            byte[] keyBytes = publicKey.getEncoded();
//            String encodedKey = new String(Base64.encodeBase64(keyBytes), "UTF-8");
//            File file = new File("clientPublicKey");
//            System.out.println("################################Client Publickey################################ \n" + encodedKey + "\n\n"  + "################################Client Publickey################################");
//            PrintWriter writer = new PrintWriter(file, "UTF-8");
//            
//            writer.println(encodedKey);
//            writer.close();
			
		} catch(IOException e) {
			System.out.println("Could not open the file : " + e.getStackTrace());
		}
		
		return public_key;
		}


	
	public PublicKey reconstruct_public_key(String algorithm, byte[] pub_key) {
	    PublicKey public_key = null;

	    try {
	        KeyFactory kf = KeyFactory.getInstance(algorithm);
	        EncodedKeySpec pub_key_spec = new X509EncodedKeySpec(pub_key);
	        public_key = kf.generatePublic(pub_key_spec);
	        
	        
	    } catch(NoSuchAlgorithmException e) {
	        System.out.println("Could not reconstruct the public key, the given algorithm oculd not be found.");
	    } catch(InvalidKeySpecException e) {
	        System.out.println("Could not reconstruct the public key");
	    }

	    return public_key;
	}
	
	public KeyPair generate_key() {
	    while(true) { // Else the compiler will complain that this procedure does not always return a "KeyPair"
	        try {
	            final KeyPairGenerator key_generator = KeyPairGenerator.getInstance("RSA");
	            key_generator.initialize(2048); // Keys of 2048 bits (minimum key length for RSA keys) are safe enough (according to the slides 128bit keys > 16 years to brute force it)

	            final KeyPair keys = key_generator.generateKeyPair();
	            return keys;
	        } catch(NoSuchAlgorithmException e) {
	            System.out.println("The given encryption algorithm (RSA) does not exist. -- generate_key() - Cryptography.");
	        }
	    }
	}
		
 
	public static void GetTimestamp(String info){
		System.out.println(info + new Timestamp((new Date()).getTime()));
	}


}
