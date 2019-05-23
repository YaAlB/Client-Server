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

public class ClientTCP extends Socket {

    private final Socket socket;
    private final OutputStream os;
    private final PrintWriter pw;
    private final OutputStreamWriter osw;
    private final InputStream is;
    private final InputStreamReader isr;
    private final BufferedReader br;
    private final Scanner input;
    private final SecretKey clientkey;
    private final SecretKeySpec serverkey;
    private final Cipher cipher;
    
    private static SecureRandom secureRandom;
    private static RSAPrivateKey privateKey;
    private static RSAPublicKey publicKey, publicKeyofClient;
    private static KeyPairGenerator keyPairGenerator;
    private static KeyPair keyPair;

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
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        clientkey = keyGenerator.generateKey();
        serverkey = getServerKey();
        System.out.println("You're now connected to the Server");
        
        GetTimestamp("Generating publickey... ");
        
        exportpublickey();
		
        GetTimestamp("Exporting sharedkey: " + "\n");
        
        exportkey();
        
        //sendClientAES();
		
		//GetTimestamp("send AUTH_REQUEST: ");
		
        sendAUTH_REQUEST();
        //sendMessage();
 
    }
  
  
    /**
     * method that allows clients to send AUTH_REQUEST() to the server, the client waits for the respond of the server
     **/
    
    private void sendAUTH_REQUEST() throws IOException {

    	GetTimestamp("Please enter Client Identity: ");
    	
        String inputmessage = input.nextLine();
        pw.println(inputmessage);
        pw.flush();
        System.out.println("Message sent to the server : " + inputmessage);
        if (inputmessage.equalsIgnoreCase("bye")) {
            System.out.println("Client is closing..");
        } else {
        	receiveAUTH_RESPONSE();
        }


    }
    
    /**
     * method that allows clients to receive AUTH_RESPONSE() from the server, the client will send it's reposne to the
     * server
     *
     **/
    
    private void receiveAUTH_RESPONSE() throws IOException {

    	GetTimestamp("recieving AUTH_RESPONSE: ");
        String receivedmessage = br.readLine();
        System.out.println("Server reply : " + receivedmessage);
        if (receivedmessage.equalsIgnoreCase("bye")) {
            System.out.println("Server sent close command");
        } else {
            sendMessage();
        }
    }

    //===================

    /**
     * method that allows clients to send messages to the server encrypt the message
     * with the server key Then the client waits for the respond of the server
     *
     **/


    private void sendMessage() throws IOException {

    	GetTimestamp("Sending Message: ");
        String inputmessage = input.nextLine();
        String tosend = encrypt(serverkey, inputmessage);
        
		JSONObject RESPONSE = new JSONObject();
		RESPONSE.put("payload", tosend);
		System.out.println(RESPONSE);
        
        pw.println(tosend);
        pw.flush();
        System.out.println("Message sent to the server : " + inputmessage);
        if (inputmessage.equalsIgnoreCase("bye")) {
            System.out.println("Client is closing..");
        } else {
            receiveMessage();
        }

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
        String dec = decrypt(clientkey, receivedmessage);
        System.out.println("Message dec from the server : " + dec);
        if (dec.equalsIgnoreCase("bye")) {
            System.out.println("Server sent close command");
        } else {
            sendMessage();
        }
    }

    public Socket getSocket() {
        return this.socket;
    }
    
    

    /**
     * method allowing the client to export it's key in a txt file
     *
     **/

    private void exportkey() {

        try {

            byte[] keyBytes = clientkey.getEncoded();
            String encodedKey = new String(Base64.encodeBase64(keyBytes), "UTF-8");
            File file = new File("clientKey");
            //System.out.println("My exported encripted key: " + encodedKey);
            PrintWriter writer = new PrintWriter(file, "UTF-8");
            writer.println(encodedKey);
            writer.close();
            
        } catch (UnsupportedEncodingException | FileNotFoundException ex) {
            Logger.getLogger(ClientTCP.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

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

    private SecretKeySpec getServerKey() {
        BufferedReader brf;
        SecretKeySpec key = null;
        try {
            brf = new BufferedReader(new FileReader("serverKey"));
            String code = brf.readLine();
            brf.close();
            //System.out.println("Client reading server encryption key from serverKey: " + code);
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
     *
     **/

    private void exportpublickey() throws NoSuchProviderException {

        try {
        	
        	secureRandom = new SecureRandom();
            try {
            	Security.addProvider(new BouncyCastleProvider());
                keyPairGenerator = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME); 
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(ClientTCP.class.getName()).log(Level.SEVERE, null, ex);
            }

            keyPairGenerator.initialize(2048, secureRandom);
            keyPair = keyPairGenerator.generateKeyPair();
            privateKey = (RSAPrivateKey) keyPair.getPrivate();
            publicKey = (RSAPublicKey) keyPair.getPublic();
        	
            byte[] keyBytes = publicKey.getEncoded();
            String encodedKey = new String(Base64.encodeBase64(keyBytes), "UTF-8");
            File file = new File("clientPublicKey");
            System.out.println("################################Client Publickey################################ \n" + encodedKey + "\n\n"  + "################################Client Publickey################################");
            PrintWriter writer = new PrintWriter(file, "UTF-8");
            GetTimestamp("Publickey has been exported");
            writer.println(encodedKey);
            writer.close();
            
        } catch (UnsupportedEncodingException | FileNotFoundException ex) {
            Logger.getLogger(ClientTCP.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
  public static void GetTimestamp(String info){
			System.out.println(info + new Timestamp((new Date()).getTime()));
	}
    
    
    

}
