/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package network.serverclient_exchange;

import java.io.BufferedReader;
import java.io.BufferedWriter;
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
import static java.lang.Thread.sleep;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
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



public class ServerTCP extends ServerSocket {

	private final ServerSocket serverSocket;
	private Socket client;
	private InputStream is;
	private InputStreamReader isr;
	private BufferedReader br;
	private SecretKeySpec clientkey;
	private final SecretKey serverkey;
	private OutputStream os;
	private OutputStreamWriter osw;
	private final KeyGenerator keyGenerator;
	private PrintWriter pw;
	private final Scanner input;

	BufferedWriter out;
	BufferedReader in;


	/**
	 * initialize the server: initialize the serverSocket, Input, keyGenerator
	 * Generate the server encryption key with the AES algo / export the key into a
	 * serverKey txt file
	 *
	 **/

	public ServerTCP(int port) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException {
		this.serverSocket = new ServerSocket(port);
		input = new Scanner(new InputStreamReader(System.in));
		keyGenerator = KeyGenerator.getInstance("AES");
		serverkey = keyGenerator.generateKey();
		exportkey();

	}


	/**
	 * listen on the port and wait for a client serverSocket.accept () initialize
	 * Input / Output StreamWriter, PrintWriter, BufferedReader generate the key of
	 * the client with the algo AES / export the key in a file txt clientKey import
	 * the client key from clientKey file put the server on hold to receive a
	 * message
	 *
	 **/

	public void getConnection() {
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
			clientkey = getClientKey();
			System.out.println("Client has connected!");
			getAUTH_REQUEST();
			//getMessage();

		} catch (IOException | InterruptedException ex) {
			Logger.getLogger(ServerTCP.class.getName()).log(Level.SEVERE, null, ex);
		}
	}

	/**
	 * method allowing the server to complete the connection close the buffer, input
	 * / output put the server on hold to receive a message
	 *
	 **/
	public void closeConnection() {
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

	/**
	 * method that allows the server to send messages to the client encrypt the
	 * message with the client's key Then the server waits for the customer to
	 * respond
	 *
	 **/

	private void sendMessage() {
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
	 *
	 **/

	private void getMessage() {
		String msg = "";
		String decmsg = "";
		byte[] result;
		try {
			msg = br.readLine();
			JSONObject RESPONSE = new JSONObject();
			RESPONSE.put("payload", msg);
			System.out.println(RESPONSE);
			//System.out.println("Crypted Message from client is " + msg);
			decmsg = decrypt(serverkey, msg);
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

	/**
	 * method allowing the server to receive AUTH_REQUEST() from the client then the server will send its response to the
	 * client
	 *
	 **/
	private void getAUTH_REQUEST() {
		String encodedKey = exportkey();
		boolean status = true;
		boolean status2 = false;
		String msg = "";

		File filePK = new File("publicKeys");

		try {
			msg = br.readLine();
			System.out.println("command" + " : " + "AUTH_REQUEST");
			System.out.println("Identity" + " : " + msg);

			FileReader fileIn = new FileReader(filePK);

			BufferedReader reader = new BufferedReader(fileIn);
			String line;

			while((line = reader.readLine()) != null) {
				if((line.contains(msg))) {
					
					System.out.println("Client " + msg + " has been verified");
					
					JSONObject RESPONSE = new JSONObject();
					RESPONSE.put("command","AUTH_RESPONSE");
					RESPONSE.put("AES128", encodedKey);
					RESPONSE.put("status", status);
					RESPONSE.put("message", "public key found");

					StringWriter out = new StringWriter();
					RESPONSE.writeJSONString(out);

					String AUTH_RESPONSE = out.toString();
					System.out.println(AUTH_RESPONSE);
					
					pw.println(AUTH_RESPONSE);
					pw.flush();
					

				}
				else {
					
					System.out.println("Client " + msg + " has been rejected");
					
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
	 * method that allows the server to import the client encryption key apart from
	 * a txt file "clientKey"
	 **/

	private SecretKeySpec getClientKey() {
		BufferedReader brf;
		SecretKeySpec key = null;
		try {
			brf = new BufferedReader(new FileReader("clientKey"));
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
	 * method allowing the client to export his key in a txt file
	 *
	 **/
	private String exportkey() {

		try {
			byte[] keyBytes = serverkey.getEncoded();
			String encodedKey = new String(Base64.encodeBase64(keyBytes), "UTF-8");
			File file = new File("serverKey");
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

}
