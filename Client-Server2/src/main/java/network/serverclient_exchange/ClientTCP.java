package network.serverclient_exchange;

import java.io.BufferedReader;
import java.io.File;
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
import java.net.InetAddress;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
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
import org.json.simple.JSONObject;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
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
import org.json.simple.parser.ParseException;
import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;

import demo.CmdLineArgs;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import org.json.simple.parser.JSONParser;
import org.json.JSONObject;


public class ClientTCP extends Socket {

    private final Socket socket;
    private final OutputStream os;
    private final PrintWriter pw;
    private final OutputStreamWriter osw;
    private final InputStream is;
    private final InputStreamReader isr;
    private final BufferedReader br;
    private final Scanner input;
//    private final SecretKey clientkey;
 //   private final SecretKeySpec serverkey;
    private final Cipher cipher;
    
    private static SecureRandom secureRandom;
    private static PrivateKey privateKey;
    private static PublicKey publicKey, publicKeyofClient;
    private static KeyPairGenerator keyPairGenerator;
    private static KeyPair keyPair;
    JSONParser parser = new JSONParser();

    /**
     * @param port 
     * @param peer 
     * @param server String: holding the server name or ip address
     **/

    public ClientTCP(String peer, int port) throws Exception {

        /**
         * initialize the client: initialize the Socket, Input / Output StreamWriter,
         * PrintWriter, BufferedReader generate the key of the client with the algo AES
         * / export the key in a file txt clientKey import the server key that is also
         * generated when the server is started allows the client to send a message to
         * the server
         *
         **/

    	
    	socket = new Socket(InetAddress.getByName(peer), port);
        os = socket.getOutputStream();
        osw = new OutputStreamWriter(os);
        pw = new PrintWriter(osw, true);
        is = socket.getInputStream();
        isr = new InputStreamReader(is);
        br = new BufferedReader(isr);
        input = new Scanner(System.in);
        cipher = Cipher.getInstance("AES");
        //KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        //clientkey = keyGenerator.generateKey();
        //serverkey = getServerKey();
        System.out.println("You're now connected to the Server");
        
        GetTimestamp("Generating publickey for Client... ");
        
        exportpublickey();
        
        GetTimestamp("Client's publickey has been exported to clientPublicKey File: ");
		
        //GetTimestamp("Exporting sharedkey: " + "\n");
        
        //exportkey();
        
        //sendClientAES();
		
		//GetTimestamp("send AUTH_REQUEST: ");
		
        GetTimestamp("Sending Authorization Request to Server: ");
        
        sendAUTH_REQUEST();
        //sendMessage();
 
        
        
        
        
        
    }
  
  
    /**
     * method that allows clients to send AUTH_REQUEST() to the server, the client waits for the respond of the server
     * @throws ParseException 
     **/
    
    private void sendAUTH_REQUEST() throws IOException, ParseException {

    	GetTimestamp("Please enter Client Identity: 'Hint aaron@krusty'");
    	
        String inputmessage = input.nextLine();
    	
    	JSONObject REQUEST = new JSONObject();
		REQUEST.put("command","AUTH_REQUEST");
		REQUEST.put("identity", inputmessage);

		StringWriter out = new StringWriter();
		REQUEST.writeJSONString(out);

		String AUTH_REQUEST = out.toString();
		GetTimestamp("Authorization Request is sent to Server: ");
		System.out.println(AUTH_REQUEST);
        //System.out.println("Message sent to the server : " + inputmessage);
        GetTimestamp("Waiting for Authorization Response from Server: ");
    	
    	//String inputmessage = "aaron@krusty";
        pw.println(AUTH_REQUEST);
        pw.flush();
        
//        if (inputmessage.equalsIgnoreCase("bye")) {
//            System.out.println("Client is closing..");
//        } else {
        receiveAUTH_RESPONSE();
//        }


    }
    
    /**
     * method that allows clients to receive AUTH_RESPONSE() from the server, the client will send it's reposne to the
     * server
     * @throws ParseException 
     *
     **/
    
    private void receiveAUTH_RESPONSE() throws IOException, ParseException {
    	
    	GetTimestamp("recieving AUTH_RESPONSE: ");
        String receivedmessage = br.readLine(); // check no response from other side
        
        GetTimestamp("Server encrypted AES128 from AUTH_RESPONSE: "+ receivedmessage);
        
        JSONObject RESPONSE = (JSONObject) parser.parse(receivedmessage);
        String status = RESPONSE.get("status").toString();
        if(status.contains("true")) {
        	String AES128SK = RESPONSE.get("AES128").toString();

        	String tosend = decrypt1(privateKey, AES128SK);

        	GetTimestamp("Client decrypted AES128 by peivatekey from AUTH_RESPONSE: "+ tosend);
        	GetTimestamp("Sharedkey has been copied to a file at Client  " );
        }else {
        	GetTimestamp("Identity is rejected, please try again ");
        	System.exit(0);
        }
        
        
        if (receivedmessage.equalsIgnoreCase("bye")) {
            System.out.println("Server sent close command");
        } else {
            sendCommand();
        }
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
	 * @throws UnsupportedEncodingException 
	 * @throws FileNotFoundException 
	 **/

	private String decrypt1(PrivateKey pkey, String encrypted) throws UnsupportedEncodingException, FileNotFoundException {
		
		//SecretKeySpec key = null;
		
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, pkey);

			byte[] original = cipher.doFinal(Base64.decodeBase64(encrypted.getBytes("UTF-8")));
			
			//key = new SecretKeySpec(original, "AES");
			
			
			
			
			//System.out.println("The server Private key: " + encodedKey);
			

			
			String original2 = new String(Base64.encodeBase64(original), "UTF-8");
			
			File file = new File("decryptedclientsharedkey");
			PrintWriter writer = new PrintWriter(file, "UTF-8");
			writer.println(original2);
			writer.close();
			

			return new String(original2);
		} catch (InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException
				| NoSuchPaddingException ex) {
			System.out.println(ex.getMessage());
		}

		return null;
	}

    //===================

    /**
     * method that allows clients to send messages to the server encrypt the message
     * with the server key Then the client waits for the respond of the server
     *
     **/


    private void sendCommand() throws IOException {

    	GetTimestamp("There are three commands. Please write in the console whether to LIST_PEERS_REQUEST, CONNECT_PEER_REQUEST or DISCONNECT_PEER_REQUEST ");
        
    	String command = input.nextLine();;
    	
    	switch(command) {
    	
    		case "LIST_PEERS_REQUEST": 
    			
    			String tosend = encrypt(getSharedKey(), command);
    	        
    			JSONObject RESPONSE = new JSONObject();
    			RESPONSE.put("payload", tosend);
    			
    	        
    	        pw.println(tosend);
    	        pw.flush();
    	        GetTimestamp("Sending LIST PEERS REQUEST Command: "+ RESPONSE);
    	        
    			
    	        receiveCommand();
    	        
    			break;
    			
    		case "CONNECT_PEER_REQUEST": 
    			
    			String tosend2 = encrypt(getSharedKey(), command);
    	        
    			JSONObject RESPONSE2 = new JSONObject();
    			RESPONSE2.put("payload", tosend2);
    			
    	        
    	        pw.println(tosend2);
    	        pw.flush();
    	        GetTimestamp("Sending CONNECT PEER REQUEST Command: " + RESPONSE2);
    	        
    			
    	        receiveCommand();
    			
    			break;
    			
    		case "DISCONNECT_PEER_REQUEST": 
    			
    			String tosend3 = encrypt(getSharedKey(), command);
    	        
    			JSONObject RESPONSE3 = new JSONObject();
    			RESPONSE3.put("payload", tosend3);
    			
    	        
    	        pw.println(tosend3);
    	        pw.flush();
    	        GetTimestamp("Sending DISCONNECT PEER REQUEST Command: " + RESPONSE3);
    	        
    			
    	        receiveCommand();
    			
    			
    			break;
    			
    		default:
    			GetTimestamp("Wrong Command, please try again : ");
    			sendCommand();
    			break;
    	}
    }
    
    private void receiveCommand() throws IOException {

    	GetTimestamp("Receiving Command Response encripted:");
    	
    	String msg = "";
		String decmsg = "";
		
        String receivedcommand = br.readLine();
        
		JSONObject RESPONSE = new JSONObject();
		RESPONSE.put("payload", receivedcommand);
		
		GetTimestamp("Command Response encripted: " + RESPONSE);
		
		
		
		decmsg = decrypt(getSharedKey(), msg);
		GetTimestamp("Decrepted Command " + decmsg);
		
		System.exit(0);
    	
    }

    /**
     * method that allows clients to receive messages from the server decrypt the
     * message with the client's key then the client will send it's reposne to the
     * server
     *
     **/

    private void receiveMessage() throws IOException {

    	GetTimestamp("Receiving Message: ");
        String receivedmessage = br.readLine();
        
        
		
        
        
        JSONObject RESPONSE = new JSONObject();
		RESPONSE.put("payload", receivedmessage);
		System.out.println(RESPONSE);
        
        //System.out.println("Message received from the server : " + receivedmessage);
        //String dec = decrypt(clientkey, receivedmessage);
        //System.out.println("Message dec from the server : " + dec);
        //if (dec.equalsIgnoreCase("bye")) {
       //     System.out.println("Server sent close command");
        //} else {
       //     sendMessage();
       // }
    }

    public Socket getSocket() {
        return this.socket;
    }
    
    

    /**
     * method allowing the client to export it's key in a txt file
     *
     **/

//    private void exportkey() {
//
//        try {
//
//            byte[] keyBytes = clientkey.getEncoded();
//            String encodedKey = new String(Base64.encodeBase64(keyBytes), "UTF-8");
//            File file = new File("clientKey");
//            //System.out.println("My exported encripted key: " + encodedKey);
//            PrintWriter writer = new PrintWriter(file, "UTF-8");
//            writer.println(encodedKey);
//            writer.close();
//            
//        } catch (UnsupportedEncodingException | FileNotFoundException ex) {
//            Logger.getLogger(ClientTCP.class.getName()).log(Level.SEVERE, null, ex);
//        }
//    }

    /**
     * method allowing the client to encrypt (asymmetric) the messages to be sent an
     * average to improve the security of these exchanges is to add to the message a
     * random vector so as not to know what to enter before "XOR" encryption
     **/
    private String encrypt(SecretKey key, String value) {
        // String initVector = "RandomInitVector";
        // IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
        try {

            cipher.init(Cipher.ENCRYPT_MODE, key);

            byte[] encrypted = cipher.doFinal(value.getBytes());

            return Base64.encodeBase64String(encrypted);
        } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException ex) {
            System.out.println(ex.getMessage());
        }

        return null;
    }

    /**
     * method allowing the client to decrypt the messages it receives from server
     * with the client key
     **/
    private String decrypt(SecretKey key, String encrypted) {
        try {

            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] original = cipher.doFinal(Base64.decodeBase64(encrypted));

            return new String(original);
        } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException ex) {
            System.out.println(ex.getMessage());
        }

        return null;
    }

    /**
     * method that allows the client to import the server encryption key from a txt
     * file "serverKey"
     **/

	private SecretKeySpec getSharedKey() {
		BufferedReader brf;
		SecretKeySpec key = null;
		try {
			brf = new BufferedReader(new FileReader("decryptedclientsharedkey"));
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
     * method allowing the client to export it's Publickey in a txt file
     * @throws NoSuchProviderException 
     * @throws IOException 
     *
     **/

    private void exportpublickey() throws NoSuchProviderException, IOException {

        try {
        	
            try {
            	//Security.addProvider(new BouncyCastleProvider());
                keyPairGenerator = KeyPairGenerator.getInstance("RSA"); 
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(ClientTCP.class.getName()).log(Level.SEVERE, null, ex);
            }

            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
            privateKey =  keyPair.getPrivate();
            publicKey = keyPair.getPublic();
        	
            byte[] keyBytes = publicKey.getEncoded();
            //GetTimestamp("Test keyBytes " + publicKey);
            String encodedKey = new String(Base64.encodeBase64(keyBytes), "UTF-8");
            File file = new File("clientPublicKey");
            File file2 = new File("readclientPublicKey");
            System.out.println("################################Client Publickey################################ \n" + encodedKey + "\n\n"  + "################################Client Publickey################################");
            
            PrintWriter writer = new PrintWriter(file, "UTF-8");
            //PrintWriter writer2 = new PrintWriter("readclientPublicKey");
            //writer2.println(publicKey.getEncoded());
            writer.println(encodedKey);
            
            FileOutputStream out = new FileOutputStream("readclientPublicKey");
            out.write(publicKey.getEncoded());
            out.close();
            //writer2.close();
            writer.close();
            
            
        } catch (UnsupportedEncodingException | FileNotFoundException ex) {
            Logger.getLogger(ClientTCP.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
  public static void GetTimestamp(String info){
			System.out.println(info + new Timestamp((new Date()).getTime()));
	}
    
    
    

}
