package network.serverclient_exchange;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.NoSuchPaddingException;

public class runClient {
	/**
	 * 
	 * Simulate a client connection with TCP/IP Protocol.
	 *
	 **/

	public static void main(String[] args) throws InvalidAlgorithmParameterException {

		/**
		 * @param server String: holding the server name or ip address
		 * @param port   int: port number We chose port 47101 because it is not
		 *               allocated. from
		 *               https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
		 *               of "Service Name and Transport Protocol Number Port Registry
		 *               Unassigned Port Number"
		 *
		 **/

		String peer = "localhost";
		int port = 47101;
		try {

			// Create a client
			ClientTCP client = new ClientTCP(peer, port);


		} catch (IOException | NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException ex) {
			Logger.getLogger(runClient.class.getName()).log(Level.SEVERE, null, ex);
		}

	}
}
