package network.serverclient_exchange;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.NoSuchPaddingException;

public class runServer {

    /**
     * 
     * Simulate a server with TCP/IP Protocol listening to port 47101 waiting for
     * connection.
     *
     **/

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException {
        /**
         * @param port int: port number We chose port 47101 because it is not allocated.
         *             from
         *             https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
         *             of "Service Name and Transport Protocol Number Port Registry
         *             Unassigned Port Number"
         *
         **/
        int port = 47101;

        try {
            // Create a server
            ServerTCP peer = new ServerTCP(port);
            // find a connection
            
            peer.getConnection();

        } catch (IOException ex) {
            Logger.getLogger(runServer.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

}
