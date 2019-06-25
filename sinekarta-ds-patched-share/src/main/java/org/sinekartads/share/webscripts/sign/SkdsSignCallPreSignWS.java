/*
 * Copyright (C) 2010 - 2012 Jenia Software.
 *
 * This file is part of Sinekarta
 *
 * Sinekarta is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Sinekarta is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
package org.sinekartads.share.webscripts.sign;

import java.lang.reflect.Array;
import java.math.BigInteger;

//import org.apache.commons.lang.ArrayUtils;
//import org.apache.commons.lang3.ArrayUtils;
import org.sinekartads.dto.domain.DocumentDTO;
import org.sinekartads.dto.domain.SignatureDTO;
import org.sinekartads.dto.domain.TimeStampRequestDTO;
import org.sinekartads.dto.request.SkdsSignRequest.SkdsPreSignRequest;
import org.sinekartads.dto.response.SkdsSignResponse.SkdsPreSignResponse;
import org.sinekartads.dto.share.SignWizardDTO;
import org.sinekartads.dto.share.SignWizardDTO.TsSelection;
import org.sinekartads.model.domain.SignDisposition;
import org.sinekartads.model.oid.DigestAlgorithm;
import org.sinekartads.share.util.AlfrescoException;
import org.sinekartads.util.TemplateUtils;
import org.springframework.extensions.webscripts.connector.ConnectorService;
import org.springframework.util.Assert;

public class SkdsSignCallPreSignWS extends BaseSignController {

	public void setConnectorService(ConnectorService connectorService) {
		this.connectorService = connectorService;
	}
	
	@Override
	protected void processData (
			SignWizardDTO dto ) 
					throws AlfrescoException {

		DocumentDTO[] documents     = dto.getDocuments();
		int last = dto.getDocuments()[0].getSignatures().length - 1;
		SignatureDTO signature = dto.getDocuments()[0].getSignatures()[last];
		//Assert.isTrue ( ArrayUtils.isNotEmpty(signature.getHexCertificateChain()) );
		Assert.isTrue (!isEmpty(signature.getHexCertificateChain()) );
		// Clone the chainSignature in order to update it without impacting on the DTO
		TsSelection tsSelection = TsSelection.valueOf(dto.getTsSelection());
		SignatureDTO chainSignature	= TemplateUtils.Instantiation.clone ( signature );
		TimeStampRequestDTO timeStampRequest = chainSignature.getTimeStampRequest();
		timeStampRequest.timestampDispositionToString(SignDisposition.TimeStamp.ENVELOPING);
		timeStampRequest.messageImprintAlgorithmToString(DigestAlgorithm.SHA256);
		timeStampRequest.nounceToString(BigInteger.ONE);
				
		// Update the nested timeStampRequest depending on the tsSelection
		switch ( tsSelection ) {
			case NONE: {
				timeStampRequest.setTsUrl ( "" );
				timeStampRequest.setTsUsername ( "" );
				timeStampRequest.setTsPassword ( "" );
				break;
			} 
			case DEFAULT: {
				timeStampRequest.setTsUrl ( conf.getTsaUrl() );
				timeStampRequest.setTsUsername ( conf.getTsaUser() );
				timeStampRequest.setTsPassword ( conf.getTsaPassword() );
				break;
			}
			default: {	}
		}
		
		// Append the updated chainSignature to the documents' signatures, at the last position:
		//		the server-tier webScripts and the signature client implementations will consider 
		//		this one as the signature to be applied 
		for ( DocumentDTO document : documents ) {
			document.setSignatures ( 
					(SignatureDTO[]) add (document.getSignatures(), chainSignature ) );
		}
		
		// Execute the pre-sign to the documents.
		SkdsPreSignRequest prereq = new SkdsPreSignRequest();
    	prereq.documentsToBase64(documents);
    	SkdsPreSignResponse dsiresp = postJsonRequest ( prereq, SkdsPreSignResponse.class );
    	documents = dsiresp.documentsFromBase64();
		dto.setDocuments(documents);
	}

	@Override
	protected int currentStep() {
		return STEP_PRESIGN;
	}
	
    /**
     * <p>Copies the given array and adds the given element at the end of the new array.</p>
     *
     * <p>The new array contains the same elements of the input
     * array plus the given element in the last position. The component type of 
     * the new array is the same as that of the input array.</p>
     *
     * <p>If the input array is <code>null</code>, a new one element array is returned
     *  whose component type is the same as the element.</p>
     * 
     * <pre>
     * ArrayUtils.add(null, null)      = [null]
     * ArrayUtils.add(null, "a")       = ["a"]
     * ArrayUtils.add(["a"], null)     = ["a", null]
     * ArrayUtils.add(["a"], "b")      = ["a", "b"]
     * ArrayUtils.add(["a", "b"], "c") = ["a", "b", "c"]
     * </pre>
     * 
     * @param array  the array to "add" the element to, may be <code>null</code>
     * @param element  the object to add
     * @return A new array containing the existing elements plus the new element
     * @since 2.1
     */
    private Object[] add(Object[] array, Object element) {
        Class type = (array != null ? array.getClass() : (element != null ? element.getClass() : Object.class));
        Object[] newArray = (Object[]) copyArrayGrow1(array, type);
        newArray[newArray.length - 1] = element;
        return newArray;
    }
    
    /**
     * Returns a copy of the given array of size 1 greater than the argument. 
     * The last value of the array is left to the default value.
     * 
     * @param array The array to copy, must not be <code>null</code>.
     * @param newArrayComponentType If <code>array</code> is <code>null</code>, create a 
     * size 1 array of this type.
     * @return A new copy of the array of size 1 greater than the input.
     */    
    private Object copyArrayGrow1(Object array, Class newArrayComponentType) {
        if (array != null) {
            int arrayLength = Array.getLength(array);
            Object newArray = Array.newInstance(array.getClass().getComponentType(), arrayLength + 1);
            System.arraycopy(array, 0, newArray, 0, arrayLength);
            return newArray;
        } else {
            return Array.newInstance(newArrayComponentType, 1);
        }
    }
    
    /**
     * <p>Checks if an array of Objects is empty or <code>null</code>.</p>
     *
     * @param array  the array to test
     * @return <code>true</code> if the array is empty or <code>null</code>
     * @since 2.1
     */
    public static boolean isEmpty(Object[] array) {
        if (array == null || array.length == 0) {
            return true;
        }
        return false;
    }
}
