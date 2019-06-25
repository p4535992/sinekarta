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

//import org.apache.commons.lang.ArrayUtils;
//import org.apache.commons.lang3.ArrayUtils;
//import org.apache.commons.lang3.StringUtils;
import org.sinekartads.dto.domain.DocumentDTO;
import org.sinekartads.dto.domain.SignatureDTO;
import org.sinekartads.dto.share.SignWizardDTO;
import org.sinekartads.share.util.AlfrescoException;
import org.springframework.util.Assert;

public class SkdsSignClientWS extends BaseSignController {

	@Override
	protected void processData(
			SignWizardDTO dto)
					throws AlfrescoException {
		
		Assert.notNull ( dto.getSignature() );
		if ( dto.getClientType().equalsIgnoreCase("KEYSTORE") ) {
			if (dto.getKsPin()==null || dto.getKsPin().trim().isEmpty()) {
				addFieldError(dto, "ksPin", getMessage(MANDATORY));
			}
			if ((dto.getKsUserAlias()==null || dto.getKsUserAlias().trim().isEmpty()) || isEmpty(dto.getSignature().getHexCertificateChain()) ) {
				addFieldError(dto, "ksUserAlias", getMessage(MANDATORY));
			}
		} else if( dto.getClientType().equalsIgnoreCase("SMARTCARD") ) {
			if (dto.getScDriver()==null || dto.getScDriver().trim().isEmpty()) {
				addFieldError(dto, "scDriver", getMessage(MANDATORY));
			}
			if (dto.getScDriver()==null || dto.getScDriver().trim().isEmpty() ) {
				addFieldError(dto, "scPin", getMessage(MANDATORY));
			}
			if ((dto.getScUserAlias()==null || dto.getScUserAlias().isEmpty()) || isEmpty(dto.getSignature().getHexCertificateChain()) ) {
				addFieldError(dto, "scUserAlias", getMessage(MANDATORY));
			}
		}
		if (isEmpty(dto.getFieldErrors()) ) {
			for ( DocumentDTO document : dto.getDocuments() ) {
				document.setSignatures(add(document.getSignatures(), dto.getSignature()));
			}
		}
	}
	
	@Override
	protected int currentStep() {
		return STEP_CLIENT;
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
    private SignatureDTO[] add(SignatureDTO[] array, SignatureDTO element) {
        Class type = (array != null ? array.getClass() : (element != null ? element.getClass() : SignatureDTO.class));
        SignatureDTO[] newArray = (SignatureDTO[]) copyArrayGrow1(array, type);
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
}
