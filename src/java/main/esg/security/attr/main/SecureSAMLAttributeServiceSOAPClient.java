/*******************************************************************************
 * Copyright (c) 2011 Earth System Grid Federation
 * ALL RIGHTS RESERVED. 
 * U.S. Government sponsorship acknowledged.
 * 
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 * 
 * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * 
 * Neither the name of the <ORGANIZATION> nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. 
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package esg.security.attr.main;

import java.io.File;

import org.apache.commons.io.FileUtils;
import org.springframework.core.io.ClassPathResource;

import esg.security.common.SOAPServiceClient;
import esg.security.utils.ssl.CertUtils;

/**
 * Example client to contact a deployed ESG SAML Attribute Service via SOAP binding.
 * This class is setup to query a SAML Attribute Service deployed on localhost on the secure port 8443,
 * and to use its own certificate and trustore to setup mutual authentication with the server.
 * 
 * Note that if the remote Attribute Service is configured with a white list of authorized clients,
 * this client's certificate subject must be included in the white list.
 * 
 */
public class SecureSAMLAttributeServiceSOAPClient {

	  // use HTTP endpoint for application deployed on localhost
	  //private static final String ENDPOINT = "https://localhost:8443/esgf-security/saml/soap/secure/attributeService.htm";
	  //private static final String ENDPOINT = "https://esg-gateway.jpl.nasa.gov/saml/soap/secure/attributeService.htm";  
	  private static final String ENDPOINT = "https://esg-datanode.jpl.nasa.gov/esgf-idp/saml/soap/secure/attributeService.htm";  
	  private static final String SAML_REQUEST = "esg/security/resources/SAMLattributeQueryRequest.xml";
	  
	  public static void main(String[] args) throws Exception {

		  // setup client certificate and trustore for mutual authentication
		  //CertUtils.setTruststore("esg/security/resources/client-trustore.ks");
		  CertUtils.setTruststore("esg/security/resources/esg-truststore.ts");
		  CertUtils.setKeystore("esg/security/resources/keystore-tomcat");
		  
		  final File file = new ClassPathResource(SAML_REQUEST).getFile();
		  final String samlRequest = FileUtils.readFileToString(file);
		  final SOAPServiceClient client = SOAPServiceClient.getInstance();
		  client.doSoap(ENDPOINT, samlRequest);
					  
	  }
	
}
