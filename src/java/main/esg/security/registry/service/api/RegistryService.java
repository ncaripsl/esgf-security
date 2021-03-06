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
package esg.security.registry.service.api;

import java.net.URL;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

import esg.security.attr.service.api.SAMLAttributeService;

/**
 * API for federation-wide registration services.
 * @author luca.cinquini
 */
public interface RegistryService {
    
    /**
     * Method to return all available attributes, as (type, description) pairs.
     * @return
     */
    Map<String, String> getAttributes();
	
	/**
	 * Method to retrieve an ordered list of {@link SAMLAttributeService} URLs that manage a given attribute type.
	 * @param attribute
	 * @return
	 */
	List<URL> getAttributeServices(String attributeType) throws UnknownPolicyAttributeTypeException;
	
	/**
	 * Method to retrieve and ordered list of RegistrationService URLs for a given attribute type.
	 * @param attributeType
	 * @return
	 * @throws UnknownPolicyAttributeTypeException
	 */
	List<URL> getRegistrationServices(String attributeType) throws UnknownPolicyAttributeTypeException;
	
	/**
	 * Method to return the white list of trusted identity providers.
	 * @return
	 */
	List<URL> getIdentityProviders();
	
	/**
     * Method to return an ordered list of authorization service endpoints.
     * @return
     */
    List<URL> getAuthorizationServices();
    
    /**
     * Method to return a list of LAS servers IP addresses.
     * @return
     */
    List<String> getLasServers();
    
    /**
     * Method to return an ordered set of Solr shards for distributed search.
     * @return
     */
    LinkedHashSet<String> getShards();
    
    /**
     * Method to set the list of shards to query.
     * @param shards
     */
    void setShards(LinkedHashSet<String> shards);

}
