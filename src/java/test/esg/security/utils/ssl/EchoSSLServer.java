package esg.security.utils.ssl;

import static esg.security.utils.ssl.TrivialCertGenerator.packKeyStore;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * A very simplistic EchoSSLServer for testing certificate interaction.
 */
public class EchoSSLServer extends Thread {
    private KeyStore keystore;
    private int sslPort = 0;
    private boolean running = false;
    private PrivateKey key;
    private Certificate[] serverCertChain;
    private char[] passPhrase;
    private ServerSocket ss;
    private KeyStore truststore;
    private byte[] echoMessage;
    private boolean verbose = false;
    
    /**
     * A fully functional EchoSSLServer. If required, configure before starting.
     */
    public EchoSSLServer() {
    }

    /**
     * @param ks keystore to use
     * @param passphare passphare to use
     */
    public void setKeystore(KeyStore ks, String passphare) {
        keystore = ks;
        passPhrase = passphare.toCharArray();
    }

    /**
     * @return the used keystore (private key)
     */
    public KeyStore getKeystore() {
        if (keystore == null) {
            try {
                keystore = packKeyStore(null, getCertChain(), key, null);
                passPhrase = "changeit".toCharArray();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return keystore;
    }
    

    private Certificate[] getCertChain() {
        if (serverCertChain == null) {
            try {
                KeyPair keyPair = TrivialCertGenerator.generateRSAKeyPair();
                serverCertChain = new Certificate[] { TrivialCertGenerator
                        .createSelfSignedCertificate(keyPair,
                                "CN=localhost, L=DE") };
                key = keyPair.getPrivate();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return serverCertChain;
    }

    /**
     * Tells the sever to use this Certificate chain and key 
     * @param key private key for the server
     * @param chain chain to use as server certificate
     * @throws UnknownHostException If the CN in the DN does not match the one from this machine.
     */
    public void setCertificate(PrivateKey key, Certificate[] chain) throws UnknownHostException {
        if (chain[0] instanceof X509Certificate ){
            String dnName = ((X509Certificate)chain[0]).getSubjectDN().getName();
            int res = dnName.indexOf("CN=") + 3;
            String cnName = dnName.substring(res, dnName.indexOf(',', res));
            InetAddress cnAdd = InetAddress.getByName(cnName);
            
            if (! (cnAdd.isAnyLocalAddress() || cnAdd.isLoopbackAddress()))
                throw new UnknownHostException("The provided hostname " + cnName 
                        + " is not the localhost.");
        }
        //clean up
        keystore = null;

        
        this.key = key;
        serverCertChain = chain;
    }
    /**
     * @param message message to echo. Set to null to cancel. If no echo message is
     * present the server will echo what it gets (interactive).
     */
    public void setMessage(String message) {
        try {
            echoMessage = message.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            echoMessage = message.getBytes();
        }
    }
    
    
    public boolean isVerbose() {
        return verbose;
    }

    /**
     * @param verbose if stacktraces from exceptions should be printed.
     */
    public void setVerbose(boolean verbose) {
        this.verbose = verbose;
    }

    /**
     * @param port server will be listening to this port after started. Set to <=0
     * to select the next free port.
     */
    public void setPort(int port) {
        sslPort = port;
    }
    
    /**
     * @return the port currently in use (if <=0 the server wasn't started yet)
     */
    public int getPort() {
        return sslPort;
    }
    
    private ServerSocket createServerSocket() throws IOException {
        SSLContext sslc;
        try {
            
            sslc = SSLContext.getInstance("SSL");
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(getKeystore(), passPhrase);
            sslc.init(kmf.getKeyManagers(), getTrustManagers(), new SecureRandom());
            
            SSLServerSocket ss;
            if (sslPort <= 0) {
                ss = (SSLServerSocket)sslc.getServerSocketFactory().createServerSocket(0);
                sslPort = ss.getLocalPort();
            } else { 
                ss = (SSLServerSocket)sslc.getServerSocketFactory().createServerSocket(
                        sslPort);
            }
            
            prepareServerSocket(ss);
            
            return ss;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new Error("No SSL in here...", e);
        } catch (KeyManagementException e) {
            e.printStackTrace();
            throw new Error("No SSL in here...", e);
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
            throw new Error("Passphrase is wrong...", e);
        } catch (KeyStoreException e) {
            e.printStackTrace();
            throw new Error("KeyStore is wrong...", e);
        }
    }

    private void prepareServerSocket(SSLServerSocket ss) {
        ss.setWantClientAuth(false);
        ss.setNeedClientAuth(truststore!=null);
    }

    private TrustManager[] getTrustManagers() throws NoSuchAlgorithmException, KeyStoreException {
        if (truststore == null) {
            return new TrustManager[] { new X509TrustManager() {
                @Override
                public X509Certificate[] getAcceptedIssuers() {return null;}
                @Override
                public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {}
                @Override
                public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {}
            }};
        } else {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
            tmf.init(truststore);
            return tmf.getTrustManagers();
        }
    }

    /**
     * @param trustStore truststore with the client certificates for client validation.
     * set to null to turn it off.
     */
    public void setValidateClient(KeyStore trustStore) {
        truststore = trustStore;
    }

    @Override
    public void run() {
        String quit = "QUIT";
        String message;
        while (running) {
            try {
                Socket socket = ss.accept();

                BufferedReader br = new BufferedReader(new InputStreamReader(
                        socket.getInputStream()));
                OutputStream out = socket.getOutputStream();
                if (echoMessage == null) {
                    message = "Welcome! Type " + quit + " to exit.\n";
                    out.write(message.getBytes());
                    String line;
                    while ((line = br.readLine()) != null) {
                        System.out.println("line: " + line);
                        message = "Echo: " + line + "\n";
                        out.write(message.getBytes());
                        if (line.equals(quit)) break;
                    }
                    out.write("Bye!\n".getBytes());
                } else {
                    out.write(echoMessage);
                }
                socket.close();
            } catch (IOException e) {
                if (verbose) e.printStackTrace();
            }
        }
    }

    @Override
    public synchronized void start() {
        if (!running) {
            running = true;
            try {
                ss = createServerSocket();
            } catch (IOException e) {
                e.printStackTrace();
                throw new Error ("Can't create server socket.");
            }
            super.start();
        } else {
            System.err.println("Already running.");
        }
    }

    public synchronized void stopServer() {
        running = false;
        if (ss != null) {
            try {
                ss.close();
            } catch (IOException e) {
            }
            ss = null;
        }
    }

}
