package esg.security.utils.ssl;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.util.Date;

import org.apache.commons.lang.ArrayUtils;

import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateExtensions;
import sun.security.x509.CertificateIssuerName;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateSubjectName;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.KeyIdentifier;
import sun.security.x509.SubjectKeyIdentifierExtension;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

public class TrivialCertGenerator {
	private static int serial = 1;
	private static ObjectIdentifier algorithm = AlgorithmId.sha1WithRSAEncryption_oid;
	
	/**
	 * @param ca ca used for signing
	 * @param caKey ca private key for signing.
	 * @param cert certificate that will get signed
	 * @return a signed certificate
	 * @throws Exception
	 */
	public static X509CertImpl sign(X509CertImpl ca, PrivateKey caKey,
			X509CertImpl cert) throws Exception {
		X509CertInfo certInfo = (X509CertInfo) cert.get(X509CertImpl.NAME + "."
				+ X509CertImpl.INFO);
		X509CertInfo caCertInfo = (X509CertInfo) ca.get(X509CertImpl.NAME + "."
				+ X509CertImpl.INFO);

		// Set the issuer
		X500Name issuer = (X500Name) caCertInfo.get(X509CertInfo.SUBJECT + "."
				+ CertificateIssuerName.DN_NAME);
		certInfo.set(
				X509CertInfo.ISSUER + "." + CertificateSubjectName.DN_NAME,
				issuer);

		certInfo.set(CertificateAlgorithmId.NAME + "."
				+ CertificateAlgorithmId.ALGORITHM, new AlgorithmId(algorithm));

		X509CertImpl newCert = new X509CertImpl(certInfo);
		newCert.sign(caKey, algorithm.toString());
		return newCert;
	}

	/**
	 * @return a keypair generated by the RSA algorithm
	 * @throws NoSuchAlgorithmException If RSA is not supported
	 * @throws Exception
	 */
	public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException  {
		KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
		kpGen.initialize(1024, new SecureRandom());
		return kpGen.generateKeyPair();
	}

	/**
	 * @param kp
	 *            KeyPair storing the keys for this certificate
	 * @param DN
	 *            The DN used when generating
	 * @return The created certificate
	 * @throws Exception
	 */
	public static X509CertImpl createSelfSignedCertificate(KeyPair kp, String DN)
			throws Exception {

		// prepare certificate info
		X509CertInfo info = new X509CertInfo();
		info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(serial++));
		info.set(
				X509CertInfo.VALIDITY,
				new CertificateValidity(new Date(), new Date(new Date()
						.getTime() + 10 * 365 * 24 * 60 * 60 * 1000L)));
		info.set(X509CertInfo.VERSION, new CertificateVersion(2));
		info.set(X509CertInfo.KEY, new CertificateX509Key(kp.getPublic()));
		X500Name subject = new X500Name(DN);

		info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(
				new AlgorithmId(algorithm)));
		info.set(X509CertInfo.SUBJECT, new CertificateSubjectName(subject));
		info.set(X509CertInfo.ISSUER, new CertificateIssuerName(subject));
		CertificateExtensions ext = new CertificateExtensions();
		ext.set(SubjectKeyIdentifierExtension.NAME,
				new SubjectKeyIdentifierExtension(new KeyIdentifier(kp
						.getPublic()).getIdentifier()));
		info.set(X509CertInfo.EXTENSIONS, ext);

		// create cert
		X509CertImpl cert = new X509CertImpl(info);
		// sign
		cert.sign(kp.getPrivate(), algorithm.toString());

		return cert;
	}
	
	/**
	 * One method for everything, not perfect but it does the work for the time being.
	 * @param ks KeyStore to use, if null a new one with pass "changeit" will be created
	 * @param chain certificate chain to use for the private key (if null no private cert set)
	 * @param key private key (if null no private cert set)
	 * @param trusted trusted certificates to add to this trustore
	 * @return the created trustore
	 * @throws Exception if anything goes wrong
	 */
	public static KeyStore packKeyStore(KeyStore ks, Certificate[] chain, PrivateKey key, Certificate[] trusted) throws Exception {
		if (ks == null) {
			ks = KeyStore.getInstance("JKS");
			//this initializes the trustore, it doesn't matter if it's empty this is required.
			ks.load(null, "changeit".toCharArray());
		}
		if (chain != null && key != null) {
		    if (chain.length > 1) {
		        //check the order is right
		        try {
		            chain[0].verify(chain[1].getPublicKey());
		        } catch (SignatureException e) {
                    //order is probably wrong! Correct it.
		            chain = chain.clone(); 
		            ArrayUtils.reverse(chain);
		            //we might assure the chain is valid indeed..
		            
                }
		        
		    }
			//save key
			ks.setKeyEntry("myKey", key, "changeit".toCharArray(), chain);
		}
		if (trusted != null) {
			for (int i = 0; i < trusted.length; i++) {
				ks.setCertificateEntry("trusted" + i, trusted[i]);
			}
			
		}
		return ks;
	}
}