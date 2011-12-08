package esg.security.utils.encryption;

import static org.junit.Assert.*;

import java.io.StringReader;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.DocumentBuilderFactory;

import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;

import com.sun.org.apache.xml.internal.serialize.OutputFormat;
import com.sun.org.apache.xml.internal.serialize.XMLSerializer;

import sun.security.x509.X509CertImpl;

import esg.security.utils.encryption.SignatureUtils.Type;
import esg.security.utils.ssl.TrivialCertGenerator;

public class SignatureUtilsTest {

    private static final String NS    = "urn:esgf:test:esg:security:utils:encryption:signatureutilstest";
    private static boolean      verbose = true;
    private static final String XML1    = "<doc xmlns='" + NS +
    		"'><item hostname='id1'>hi there...</item><item hostname='id2'>hi there too...</item></doc>";
    private static final String XML2    = "<doc><item1 id='item1'>hi there...</item1><item2 id='item2'>hi there too...</item2></doc>";

    private void showXML(Document doc) throws Exception {
        if (verbose) {
            // output it to see...
            OutputFormat format = new OutputFormat(doc);
            format.setLineWidth(65);
            format.setIndenting(true);
            format.setIndent(2);
            XMLSerializer serializer = new XMLSerializer(System.out, format);
            serializer.serialize(doc);
        }
    }

    @Test
    public void testByteArray2Hex() {
        byte[][] bytes = new byte[][] { new byte[] { 1 }, new byte[] { 16 },
                new byte[] { 1, 1, 1 }, new byte[] { 15, 15, 15 },
                new byte[] { 127, -128, -1 } };
        String[] strings = new String[] { "01", "10", "010101", "0f0f0f",
                "7f80ff" };

        for (int i = 0; i < strings.length; i++) {
            String resultStr = SignatureUtils.byteArray2Hex(bytes[i]);
            byte[] resultBytesLow = SignatureUtils.hex2ByteArray(strings[i]
                    .toUpperCase());
            byte[] resultBytesUp = SignatureUtils.hex2ByteArray(strings[i]
                    .toLowerCase());

            assertEquals(strings[i], resultStr);
            // asure both upper and lowercase works
            assertArrayEquals(bytes[i], resultBytesLow);
            assertArrayEquals(bytes[i], resultBytesUp);

        }
    }

    @Test
    public void testSignVerify() throws Exception {
        KeyPair kp = TrivialCertGenerator.generateRSAKeyPair();
        String algorithm = "SHA1withRSA";
        String test = "This is a test string. Yes, really.";

        byte[] signature = SignatureUtils.sign(test.getBytes(),
                                               kp.getPrivate(), algorithm);
        // System.out.printf("Signature: %s\n",
        // SignatureUtils.byteArray2Hex(signature));

        boolean result = SignatureUtils.verify(test.getBytes(), signature, kp
                .getPublic(), algorithm);
        assertTrue("Signature doesn't match!", result);
    }

    @Test
    public void testSignVerifyWithCert() throws Exception {
        KeyPair kp = TrivialCertGenerator.generateRSAKeyPair();
        X509CertImpl cert = TrivialCertGenerator
                .createSelfSignedCertificate(kp, "CN=Test");
        String test = "This is also a test string. Yes, really.";

        String signature = SignatureUtils.sign(test, kp.getPrivate());
        // System.out.printf("Signature: %s\n", signature);

        boolean result = SignatureUtils.verify(test, signature, cert);
        assertTrue("Signature doesn't match!", result);
    }
    
    
    @Test
    public void testXMLSignatureID() throws Exception {
        // Instantiate the document to be signed.
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = dbf.newDocumentBuilder().parse(new InputSource(
                                                              new StringReader(
                                                                      XML1)));

        // generate signing/validating data (certificate + private key)
        KeyPair kp = TrivialCertGenerator.generateRSAKeyPair();
        X509Certificate certificate = TrivialCertGenerator
                .createSelfSignedCertificate(kp, "O=Testing Inc., CN=test");

        // assert we have no signature yet
        assertEquals("Unexpected Signature element found!", 0, doc
                .getElementsByTagNameNS(XMLSignature.XMLNS, "Signature")
                .getLength());

        // sign everything (root element)
        Node signedNode = doc.getDocumentElement();

        // sign the whole document
        SignatureUtils.signXMLNode(certificate, kp.getPrivate(), signedNode);

        showXML(doc);

        // assert we have a single signature element
        assertEquals("Unexpected number of Signature elements found!", 1, doc
                .getElementsByTagNameNS(XMLSignature.XMLNS, "Signature")
                .getLength());

        // ** Now proceed to validation
        try {
            SignatureUtils.validateXMLNode(signedNode);
        } catch (Exception e) {
            e.printStackTrace();
            fail("XML could not get validated as expected");
        }
    }

    @Test
    public void testXMLSignatureEnveloping() throws Exception {
        // Instantiate the document to be signed.
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = dbf.newDocumentBuilder().parse(new InputSource(
                                                              new StringReader(
                                                                      XML1)));

        // generate signing/validating data (certificate + private key)
        KeyPair kp = TrivialCertGenerator.generateRSAKeyPair();
        X509Certificate certificate = TrivialCertGenerator
                .createSelfSignedCertificate(kp, "O=Testing Inc., CN=test");

        // assert we have no signature yet
        assertEquals("Unexpected Signature element found!", 0, doc
                .getElementsByTagNameNS(XMLSignature.XMLNS, "Signature")
                .getLength());

        // sign everything (root element)
        Node signedNode = doc.getDocumentElement();

        // sign the whole document
        SignatureUtils.signXMLNodeEnveloping(certificate, kp.getPrivate(),
                                             signedNode);

        showXML(doc);

        // assert we have a single signature element
        assertEquals("Unexpected number of Signature elements found!", 1, doc
                .getElementsByTagNameNS(XMLSignature.XMLNS, "Signature")
                .getLength());

        // ** Now proceed to validation
        try {
            SignatureUtils.validateXMLNode(signedNode, Type.ENVELOPING);
        } catch (Exception e) {
            e.printStackTrace();
            fail("XML could not get validated as expected");
        }
    }

    @Test
    public void testXMLSignatureTampering() throws Exception {
        // Instantiate the document to be signed.
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = dbf.newDocumentBuilder().parse(new InputSource(
                                                              new StringReader(
                                                                      XML1)));

        // generate signing/validating data (certificate + private key)
        KeyPair kp = TrivialCertGenerator.generateRSAKeyPair();
        X509Certificate certificate = TrivialCertGenerator
                .createSelfSignedCertificate(kp, "O=Testing Inc., CN=test");

        // assert we have no signature yet
        assertEquals("Unexpected Signature element found!", 0, doc
                .getElementsByTagNameNS(XMLSignature.XMLNS, "Signature")
                .getLength());

        // sign everything (root element)
        Node signedNode = doc.getDocumentElement();

        // sign the whole document
        SignatureUtils.signXMLNode(certificate, kp.getPrivate(), signedNode);

        // Now Modify the XML
        Node modNode = signedNode.getFirstChild().getFirstChild();
        assertEquals(Node.TEXT_NODE, modNode.getNodeType());
        String oldStr = modNode.getNodeValue();
        oldStr = (oldStr.charAt(0) == 'X' ? "-" : "X") + oldStr.substring(1);
        modNode.setNodeValue(oldStr);

        showXML(doc);

        // assert we have a single signature element
        assertEquals("Unexpected number of Signature elements found!", 1, doc
                .getElementsByTagNameNS(XMLSignature.XMLNS, "Signature")
                .getLength());

        // ** Now proceed to validation
        try {
            SignatureUtils.validateXMLNode(signedNode);
            fail("Tampered XML got validated!!");
        } catch (Exception e) {
            if (!(e instanceof XMLSignatureException)) {
                fail("Unexpected Exception.");
            }
        }
    }

    @Test
    public void testXMLInternalNode() throws Exception {
        // Instantiate the document to be signed.
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = dbf.newDocumentBuilder().parse(new InputSource(
                                                              new StringReader(
                                                                      XML1)));

        // generate signing/validating data (certificate + private key)
        KeyPair kp = TrivialCertGenerator.generateRSAKeyPair();
        X509Certificate certificate = TrivialCertGenerator
                .createSelfSignedCertificate(kp, "O=Testing Inc., CN=test");

        // assert we have no signature yet
        assertEquals("Unexpected Signature element found!", 0, doc
                .getElementsByTagNameNS(XMLSignature.XMLNS, "Signature")
                .getLength());

        // sign only the first sub node
        Node signedNode = doc.getDocumentElement().getFirstChild();

        // sign the node
        SignatureUtils.signXMLNode(certificate, kp.getPrivate(), signedNode);

        showXML(doc);

        // assert we have a single signature element
        assertEquals("Unexpected number of Signature elements found!", 1, doc
                .getElementsByTagNameNS(XMLSignature.XMLNS, "Signature")
                .getLength());

        // ** Now proceed to validation
        try {
            SignatureUtils.validateXMLNode(signedNode);
        } catch (Exception e) {
            e.printStackTrace();
            fail("XML could not get validated as expected");
        }

        // ** Try to validate a different node
        try {
            SignatureUtils.validateXMLNode(signedNode.getNextSibling());
            fail("XML should not have been validated.");
        } catch (Exception e) {
            // fine
        }
    }

    @Test
    public void testXMLInternalNodeTampering() throws Exception {
        // Instantiate the document to be signed.
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = dbf.newDocumentBuilder().parse(new InputSource(
                                                              new StringReader(
                                                                      XML2)));

        // generate signing/validating data (certificate + private key)
        KeyPair kp = TrivialCertGenerator.generateRSAKeyPair();
        X509Certificate certificate = TrivialCertGenerator
                .createSelfSignedCertificate(kp, "O=Testing Inc., CN=test");

        // assert we have no signature yet
        assertEquals("Unexpected Signature element found!", 0, doc
                .getElementsByTagNameNS(XMLSignature.XMLNS, "Signature")
                .getLength());

        // sign only the first sub node
        Node signedNode = doc.getDocumentElement().getFirstChild();

        // sign the node
        SignatureUtils.signXMLNode(certificate, kp.getPrivate(), signedNode);

        // Now Modify the XML "OUTSIDE" of the signed time
        doc.getDocumentElement().appendChild(doc.createElement("newItem"));
        // signedNode.getNextSibling().appendChild(doc.createElement("newItem"));

        showXML(doc);

        // assert we have a single signature element
        assertEquals("Unexpected number of Signature elements found!", 1, doc
                .getElementsByTagNameNS(XMLSignature.XMLNS, "Signature")
                .getLength());

        // ** Now proceed to validation
        try {
            SignatureUtils.validateXMLNode(signedNode);
        } catch (Exception e) {
            e.printStackTrace();
            fail("XML could not get validated as expected");
        }

        // now change the node we are validating
        signedNode.appendChild(doc.createElement("newItem"));

        showXML(doc);

        // ** Try to validate a different node
        try {
            SignatureUtils.validateXMLNode(signedNode);
            fail("XML should not have been validated.");
        } catch (Exception e) {
            // fine
        }
    }

    @Test
    public void testXMLMultipleNodes() throws Exception {
        // Instantiate the document to be signed.
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = dbf.newDocumentBuilder().parse(new InputSource(
                                                              new StringReader(
                                                                      XML2)));

        // generate signing/validating data (certificate + private key)
        KeyPair kp1 = TrivialCertGenerator.generateRSAKeyPair();
        KeyPair kp2 = TrivialCertGenerator.generateRSAKeyPair();
        X509Certificate certificate1 = TrivialCertGenerator
                .createSelfSignedCertificate(kp1, "O=Testing Inc., CN=test1");
        X509Certificate certificate2 = TrivialCertGenerator
                .createSelfSignedCertificate(kp2, "O=Testing Inc., CN=test2");

        // assert we have no signature yet
        assertEquals("Unexpected Signature element found!", 0, doc
                .getElementsByTagNameNS(XMLSignature.XMLNS, "Signature")
                .getLength());

        // sign only the first sub node
        Node signedNode1 = doc.getDocumentElement().getFirstChild();
        Node signedNode2 = doc.getDocumentElement().getFirstChild()
                .getNextSibling();

        // sign the whole document
        SignatureUtils.signXMLNode(certificate1, kp1.getPrivate(), signedNode1);
        SignatureUtils.signXMLNode(certificate2, kp2.getPrivate(), signedNode2);

        showXML(doc);

        // assert we have a single signature element
        assertEquals("Unexpected number of Signature elements found!", 2, doc
                .getElementsByTagNameNS(XMLSignature.XMLNS, "Signature")
                .getLength());

        // ** Now proceed to validation
        try {
            SignatureUtils.validateXMLNode(signedNode1);
        } catch (Exception e) {
            e.printStackTrace();
            fail("XML could not get validated as expected");
        }
        // ** Now proceed to validation
        try {
            SignatureUtils.validateXMLNode(signedNode2);
        } catch (Exception e) {
            e.printStackTrace();
            fail("XML could not get validated as expected");
        }

        // ** Try to validate from root using the default node method
        try {
            SignatureUtils.validateXMLNode(doc.getDocumentElement());
            fail("XML should not have been validated.");
        } catch (Exception e) {
            // fine
        }

        // ** Now Try to validate from root using the proper root method
        try {
            int signatures = SignatureUtils.validateXML(doc);
            assertEquals(2, signatures);
        } catch (Exception e) {
            e.printStackTrace();
            fail("XML could not get validated as expected");
        }
    }

    @Test
    public void testXMLSigantureTampering() throws Exception {
    }
}
