package esg.security.utils.encryption;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;

import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class SignatureUtils {
    public static final String DEFAULT_ALGORITHM         = "SHA1withRSA";
    public static final String DEFAULT_CHARSET           = "UTF-8";
    public static final String DEFAULT_XMLDIGEST         = DigestMethod.SHA1;
    public static final String DEFAULT_XMLSIGN_ALGORITHM = SignatureMethod.RSA_SHA1;

    public static enum Type {
        ENVELOPING, ENVELOPED, DETACHED
    }

    private static final char[] hex = { '0', '1', '2', '3', '4', '5', '6', '7',
            '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

    /**
     * @param bytes
     *            input bytes
     * @return string with the hexadecimal representation of the byte array.
     */
    public static String byteArray2Hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (final byte b : bytes) {
            sb.append(hex[(b & 0xF0) >> 4]);
            sb.append(hex[b & 0x0F]);
        }
        return sb.toString();
    }

    /**
     * @param hexStr
     *            hex string
     * @return the resulting parsed byte array
     */
    public static byte[] hex2ByteArray(String hexStr) {
        int len = hexStr.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hexStr.charAt(i), 16) << 4) + Character
                    .digit(hexStr.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * Sign an UTF-8 message using the {@value #DEFAULT_ALGORITHM} algorithm and
     * return the signature as a hex string.
     * 
     * @param message
     *            message string to get signed (Must be in
     *            {@value #DEFAULT_CHARSET}).
     * @param privKey
     *            private key for signing it.
     * @return String representation in hexadecimal format of the signature.
     * @throws InvalidKeyException
     *             If key can't be used for signing.
     * @throws UnsupportedEncodingException
     *             If {@value #DEFAULT_CHARSET} is not supported in the running
     *             VM.
     * @throws NoSuchAlgorithmException
     *             If {@value #DEFAULT_ALGORITHM} is not available.
     * @throws SignatureException
     *             If the signing procedure failed.
     */
    public static String sign(String message, PrivateKey privKey)
            throws InvalidKeyException, UnsupportedEncodingException,
            NoSuchAlgorithmException, SignatureException {

        return byteArray2Hex(sign(message.getBytes(DEFAULT_CHARSET), privKey,
                                  DEFAULT_ALGORITHM));
    }

    /**
     * Sign a message (i.e. digest and the encode using private key + salt).
     * 
     * @param message
     *            Message to be signed.
     * @param privKey
     *            private key to be used for signing.
     * @param signingAlg
     *            signing algorithm.
     * @return the signature.
     * @throws NoSuchAlgorithmException
     *             if signing algorithm is not supported.
     * @throws InvalidKeyException
     *             if the key can't be used for signing.
     * @throws SignatureException
     *             if the signature procedure failed.
     */
    public static byte[] sign(byte[] message, PrivateKey privKey,
            String signingAlg) throws NoSuchAlgorithmException,
            InvalidKeyException, SignatureException {
        Signature sign = Signature.getInstance(signingAlg);
        sign.initSign(privKey);
        sign.update(message);
        return sign.sign();
    }

    /**
     * Verify a given {@value #DEFAULT_CHARSET} encoded message using a
     * certificate.
     * 
     * @param message
     *            message to verify.
     * @param signature
     *            message's signature.
     * @param cert
     *            Certificate used for verifying.
     * @return
     * @throws NoSuchAlgorithmException
     *             if {@value #DEFAULT_ALGORITHM} is not supported.
     * @throws InvalidKeyException
     *             if the key can't be used for verification.
     * @throws SignatureException
     *             if the verification procedure failed.
     * @throws UnsupportedEncodingException
     *             If {@value #DEFAULT_CHARSET} is not available or the message
     *             can't be decoded using this procedure.
     */
    public static boolean verify(String message, String signature,
            Certificate cert) throws InvalidKeyException,
            NoSuchAlgorithmException, SignatureException,
            UnsupportedEncodingException {
        return verify(message.getBytes(DEFAULT_CHARSET),
                      hex2ByteArray(signature), cert.getPublicKey(),
                      DEFAULT_ALGORITHM);
    }

    /**
     * Verify that the given message and signature matches.
     * 
     * @param message
     *            message to verify.
     * @param signature
     *            message's signature.
     * @param pubKey
     *            public key.
     * @param signingAlg
     *            signing algorithm.
     * @return if the verification succeeded.
     * @throws NoSuchAlgorithmException
     *             if signing algorithm is not supported.
     * @throws InvalidKeyException
     *             if the key can't be used for verification.
     * @throws SignatureException
     *             if the verification procedure failed.
     */
    public static boolean verify(byte[] message, byte[] signature,
            PublicKey pubKey, String signingAlg)
            throws NoSuchAlgorithmException, InvalidKeyException,
            SignatureException {
        Signature sign = Signature.getInstance(signingAlg);
        sign.initVerify(pubKey);
        sign.update(message);
        return sign.verify(signature);
    }

    /**
     * Sign a node using {@value #DEFAULT_XMLSIGN_ALGORITHM} in a enveloped
     * modus (within signed node).
     * 
     * @param certificate
     *            X509Ceertificate signing this node.
     * @param privKey
     *            private key used for signing this node.
     * @param nodeToSign
     *            Node to be signed.
     * @throws NoSuchAlgorithmException
     *             If Digest/Encryption algorithm is not Supported.
     * @throws InvalidAlgorithmParameterException
     *             if Algorithms aren't properly initiated.(should never
     *             happen).
     * @throws MarshalException
     *             If xml can't be marshalled.
     * @throws XMLSignatureException
     *             signature procedure failed.
     */
    public static void signXMLNode(X509Certificate certificate,
            PrivateKey privKey, Node nodeToSign)
            throws NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, MarshalException,
            XMLSignatureException {
        // Create a DOM XMLSignatureFactory that will be used to
        // generate the enveloped signature.
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

        // we need an id. It might not be unique, if it's not I suppose every
        // node with the same id will get signed... not sure though.
        // We should have unique ids here or test it more properly.
        Node att = nodeToSign.getAttributes().getNamedItem("id");
        if (att == null) {
            att = nodeToSign.getOwnerDocument().createAttribute("id");
            att.setNodeValue(UUID.randomUUID().toString());
            nodeToSign.getAttributes().setNamedItem(att);
        }
        String reference = "#" + att.getNodeValue();

        // Create a Reference to the enveloped document (in this case,
        // you are signing the whole document, so a URI of "" signifies
        // that, and also specify the SHA1 digest algorithm and
        // the ENVELOPED Transform.
        Reference ref = fac
                .newReference(reference,
                              fac.newDigestMethod(DEFAULT_XMLDIGEST, null),
                              Collections
                                      .singletonList(fac
                                              .newTransform(Transform.ENVELOPED,
                                                            (TransformParameterSpec) null)),
                              null, null);

        // Create the SignedInfo.
        SignedInfo si = fac
                .newSignedInfo(fac.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE,
                                                             (C14NMethodParameterSpec) null),
                               fac.newSignatureMethod(DEFAULT_XMLSIGN_ALGORITHM,
                                                      null), Collections
                                       .singletonList(ref));
        // Create the KeyInfo containing the X509Data.
        KeyInfoFactory kif = fac.getKeyInfoFactory();
        List<Object> x509Content = new ArrayList<Object>();
        x509Content.add(certificate.getSubjectX500Principal().getName());
        x509Content.add(certificate);
        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(kif
                .newX509Data(x509Content)));

        // Create a DOMSignContext and specify the RSA PrivateKey and
        // location of the resulting XMLSignature's parent element.
        DOMSignContext dsc = new DOMSignContext(privKey, nodeToSign);

        // Create the XMLSignature, but don't sign it yet.
        XMLSignature xmlSig = fac.newXMLSignature(si, ki);

        // Marshal, generate, and sign the enveloped signature.
        xmlSig.sign(dsc);
    }

//    public static void signXMLNode(X509Certificate certificate,
//            PrivateKey privKey, Node nodeToSign, String Xpath)
//            throws NoSuchAlgorithmException,
//            InvalidAlgorithmParameterException, MarshalException,
//            XMLSignatureException {
//        
//        if (true) throw new Error("Method not implemented");
//
//        // Create a DOM XMLSignatureFactory that will be used to
//        // generate the enveloped signature.
//        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
//
//        // Create a Reference to the enveloped document (in this case,
//        // you are signing the whole document, so a URI of "" signifies
//        // that, and also specify the SHA1 digest algorithm and
//        // the ENVELOPED Transform.
//        Reference ref = fac
//                .newReference("",
//                              fac.newDigestMethod(DEFAULT_XMLDIGEST, null),
//                              Collections
//                                      .singletonList(fac
//                                              .newTransform(Transform.ENVELOPED,
//                                                            (TransformParameterSpec) null)),
//                              null, null);
//
//        // Create the SignedInfo.
//        SignedInfo si = fac
//                .newSignedInfo(fac.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE,
//                                                             (C14NMethodParameterSpec) null),
//                               fac.newSignatureMethod(DEFAULT_XMLSIGN_ALGORITHM,
//                                                      null), Collections
//                                       .singletonList(ref));
//        // Create the KeyInfo containing the X509Data.
//        KeyInfoFactory kif = fac.getKeyInfoFactory();
//        List<Object> x509Content = new ArrayList<Object>();
//        x509Content.add(certificate.getSubjectX500Principal().getName());
//        x509Content.add(certificate);
//        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(kif
//                .newX509Data(x509Content)));
//
//        // Create a DOMSignContext and specify the RSA PrivateKey and
//        // location of the resulting XMLSignature's parent element.
//        DOMSignContext dsc = new DOMSignContext(privKey, nodeToSign);
//
//        // Create the XMLSignature, but don't sign it yet.
//        XMLSignature xmlSig = fac.newXMLSignature(si, ki);
//
//        // Marshal, generate, and sign the enveloped signature.
//        xmlSig.sign(dsc);
//    }

    public static void signXMLNodeEnveloping(X509Certificate certificate,
            PrivateKey privKey, Node nodeToSign)
            throws NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, MarshalException,
            XMLSignatureException {
        // Create a DOM XMLSignatureFactory that will be used to
        // generate the enveloped signature.
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

        XMLObject obj = fac
                .newXMLObject(Collections.singletonList(new DOMStructure(
                        nodeToSign)), "signed", null, null);
        Reference ref = fac.newReference("#signed", fac
                .newDigestMethod(DEFAULT_XMLDIGEST, null));

        // Create the SignedInfo.
        SignedInfo si = fac
                .newSignedInfo(fac.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE,
                                                             (C14NMethodParameterSpec) null),
                               fac.newSignatureMethod(DEFAULT_XMLSIGN_ALGORITHM,
                                                      null), Collections
                                       .singletonList(ref));
        // Create the KeyInfo containing the X509Data.
        KeyInfoFactory kif = fac.getKeyInfoFactory();
        List<Object> x509Content = new ArrayList<Object>();
        x509Content.add(certificate.getSubjectX500Principal().getName());
        x509Content.add(certificate);
        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(kif
                .newX509Data(x509Content)));

        // Create a DOMSignContext and specify the RSA PrivateKey and
        // location of the resulting XMLSignature's parent element.
        DOMSignContext dsc = new DOMSignContext(privKey, nodeToSign
                .getParentNode());

        // Create the XMLSignature, but don't sign it yet.
        XMLSignature xmlSig = fac.newXMLSignature(si, ki, Collections
                .singletonList(obj), null, null);

        // Marshal, generate, and sign the enveloped signature.
        xmlSig.sign(dsc);
    }

    /**
     * Verifies the signature for an enveloped node. Everything within its
     * subtree will be compared to the enclosed signature).
     * 
     * @param nodeToValidate
     *            the root node of the subtree that will be validated. It must
     *            contain a proper Signature Element as a child, although it is
     *            not required to be the last one.
     * @throws XMLSignatureException
     *             Verification failed.
     * @throws MarshalException
     *             Can't unmarshal the xml signature.
     */
    public static void validateXMLNode(Node nodeToValidate)
            throws XMLSignatureException, MarshalException {
        validateXMLNode(nodeToValidate, Type.ENVELOPED);
    }

    /**
     * Verifies the signature for eider an enveloped or enveloping node.
     * 
     * @param nodeToValidate
     *            the root node of the subtree that will be validated. It must
     *            contain a proper Signature Element as a child, although it is
     *            not required to be the last one.
     * @throws XMLSignatureException
     *             Verification failed.
     * @throws MarshalException
     *             Can't unmarshal the xml signature.
     */
    public static void validateXMLNode(Node nodeToValidate, Type type)
            throws XMLSignatureException, MarshalException {
        Node signingNode = null;
        switch (type) {
        case ENVELOPED:
            NodeList nl = nodeToValidate.getOwnerDocument()
                    .getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
            if (nl.getLength() != 0) {
                for (int i = 0; i < nl.getLength(); i++) {
                    if (nl.item(i).getParentNode() == nodeToValidate) {
                        signingNode = nl.item(i);
                        break;
                    }
                }
            }
            break;
        case ENVELOPING:
            // Signature/Object/nodeToValidate
            signingNode = nodeToValidate.getParentNode().getParentNode();
            if (signingNode.getNodeName() != "Signature"
                    || signingNode.getNamespaceURI() != XMLSignature.XMLNS) {
                // not the node we were looking
                signingNode = null;
            }
            break;
        default:
            throw new Error(
                    "Can't find the detached signature of this node at the moment.");
        }

        if (signingNode == null) throw new XMLSignatureException(
                "Cannot find Signature element within the given node.");

        validateXMLFromSigningNode(signingNode);
    }

    /**
     * Verifies the signature for an enveloped node. Everything within its
     * subtree will be compared to the enclosed signature).
     * 
     * @param signingNode
     *            The node containing the signature. We assumed here an
     *            enveloped modus, so we are validating from the parent of this
     *            node onwards.
     * @throws XMLSignatureException
     *             Verification failed.
     * @throws MarshalException
     *             Can't unmarshal the xml signature.
     */
    private static void validateXMLFromSigningNode(Node signingNode)
            throws XMLSignatureException, MarshalException {
        DOMValidateContext valContext = new DOMValidateContext(
                new X509KeySelector(), signingNode);

        // Unmarshal the XMLSignature.
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
        XMLSignature xmlSignature2 = fac.unmarshalXMLSignature(valContext);

        // Validate the XMLSignature.
        boolean coreValidity = xmlSignature2.validate(valContext);

        // Check core validation status.
        if (coreValidity == false) {
            System.err.println("Signature failed core validation");
            boolean sv = xmlSignature2.getSignatureValue().validate(valContext);
            System.out.println("signature validation status: " + sv);
            if (sv == false) {
                // Check the validation status of each Reference.
                @SuppressWarnings("rawtypes")
                Iterator i = xmlSignature2.getSignedInfo().getReferences()
                        .iterator();
                for (int j = 0; i.hasNext(); j++) {
                    boolean refValid = ((Reference) i.next())
                            .validate(valContext);
                    System.out.println("ref[" + j + "] validity status: "
                            + refValid);
                }
            }
            throw new XMLSignatureException("XML is not valid.");
        } else {
            System.out.println("Signature passed core validation");
        }
    }

    /**
     * Verifies all signatures found in the document and returns the number of
     * found ones. Signatures are assumed to be written in "enveloped" modus.
     * This method doesn't fail if there are no signature present, in such a
     * case it will merely return 0.
     * 
     * @param nodeToValidate
     *            the root node of the subtree that will be validated. It must
     *            contain a proper Signature Element as a child, although it is
     *            not required to be the last one.
     * @throws XMLSignatureException
     *             Verification failed.
     * @throws MarshalException
     *             Can't unmarshal the xml signature.
     */
    public static int validateXML(Document doc) throws XMLSignatureException,
            MarshalException {
        NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS,
                                                 "Signature");
        if (nl.getLength() != 0) {
            for (int i = 0; i < nl.getLength(); i++) {
                validateXMLFromSigningNode(nl.item(i));
            }
        }

        return nl.getLength();
    }


    private static class X509KeySelector extends KeySelector {
        @SuppressWarnings("rawtypes")
        public KeySelectorResult select(KeyInfo keyInfo,
                KeySelector.Purpose purpose, AlgorithmMethod method,
                XMLCryptoContext context) throws KeySelectorException {
            Iterator ki = keyInfo.getContent().iterator();
            while (ki.hasNext()) {
                XMLStructure info = (XMLStructure) ki.next();
                if (!(info instanceof X509Data)) continue;
                X509Data x509Data = (X509Data) info;
                Iterator xi = x509Data.getContent().iterator();
                while (xi.hasNext()) {
                    Object o = xi.next();
                    if (!(o instanceof X509Certificate)) continue;
                    final PublicKey key = ((X509Certificate) o).getPublicKey();
                    // Make sure the algorithm is compatible
                    // with the method.
                    if (algEquals(method.getAlgorithm(), key.getAlgorithm())) {
                        return new KeySelectorResult() {
                            public Key getKey() {
                                return key;
                            }
                        };
                    }
                }
            }
            throw new KeySelectorException("No key found!");
        }

        static boolean algEquals(String algURI, String algName) {
            if ((algName.equalsIgnoreCase("DSA") && algURI
                    .equalsIgnoreCase(SignatureMethod.DSA_SHA1))
                    || (algName.equalsIgnoreCase("RSA") && algURI
                            .equalsIgnoreCase(SignatureMethod.RSA_SHA1))) {
                return true;
            } else {
                return false;
            }
        }
    }
}
