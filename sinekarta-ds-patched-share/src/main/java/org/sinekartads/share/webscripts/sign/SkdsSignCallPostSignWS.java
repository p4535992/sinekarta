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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

//import org.apache.commons.lang.ArrayUtils;
//import org.apache.commons.lang3.ArrayUtils;
//import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import org.sinekartads.dto.domain.DocumentDTO;
import org.sinekartads.dto.domain.SignatureDTO;
import org.sinekartads.dto.request.SkdsSignRequest.SkdsPostSignRequest;
import org.sinekartads.dto.response.SkdsSignResponse.SkdsPostSignResponse;
import org.sinekartads.dto.share.SignWizardDTO;
import org.sinekartads.model.domain.DigestInfo;
import org.sinekartads.model.oid.EncryptionAlgorithm;
import org.sinekartads.model.oid.SignatureAlgorithm;
import org.sinekartads.share.util.AlfrescoException;
import org.sinekartads.util.x509.X509Utils;
import org.springframework.extensions.webscripts.connector.ConnectorService;
import org.springframework.util.Assert;

public class SkdsSignCallPostSignWS extends BaseSignController {

	public void setConnectorService(ConnectorService connectorService) {
		this.connectorService = connectorService;
	}

	private static Logger tracer = Logger
			.getLogger(SkdsSignCallPostSignWS.class);

	@Override
	protected void processData(SignWizardDTO dto) throws AlfrescoException {

		DocumentDTO[] documents     = dto.getDocuments();
		int last = dto.getDocuments()[0].getSignatures().length - 1;
		SignatureDTO signature = dto.getDocuments()[0].getSignatures()[last];

		byte[] digitalSignature = null;
		if (dto.getClientType().equalsIgnoreCase("KEYSTORE")) {
			try {
				SignatureAlgorithm sigAlgorithm = SignatureAlgorithm.getInstance(signature.getSignAlgorithm());
				EncryptionAlgorithm encryptionAlgorithm = sigAlgorithm.getEncryptionAlgorithm();
				DigestInfo digestInfo = converter.toDigestInfo(signature.getDigest());
				PrivateKey privateKey = X509Utils.privateKeyFromHex(dto.getKsHexPrivateKey(), encryptionAlgorithm);
				// use a wrapped cipher algorithm
				byte[] prefix = new byte[] { 0x30, 0x2f, 0x30, 0x0b, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x04, 0x20 };
				byte[] fingerPrint;
				// append the digest to the prefix
				fingerPrint = addAll(prefix, digestInfo.getFingerPrint());
				// apply the digital signature
				Cipher cipher = Cipher.getInstance(encryptionAlgorithm.getName());
				cipher.init(Cipher.ENCRYPT_MODE, privateKey);
				digitalSignature = cipher.doFinal(fingerPrint);
			} catch (Exception e) {
				processError(dto, String.format("%s - %s", getMessage(GENERIC_ERROR), e.getMessage()));
			}
		} else if (dto.getClientType().equalsIgnoreCase("SMARTCARD") ) {
			digitalSignature = signature.digitalSignatureFromHex();
			//Assert.isTrue ( ArrayUtils.isNotEmpty(digitalSignature) );
			Assert.isTrue (!isEmpty(digitalSignature) );
		} else {
			throw new UnsupportedOperationException(
					String.format("unsupported signature client - %s, use SMARTCARD or KEYSTORE instead.", dto.getClientType()));
		}
		
		// call the postSign service
		signature.digitalSignatureToHex(digitalSignature);
		SkdsPostSignRequest postreq = new SkdsPostSignRequest();
		postreq.documentsToBase64(documents);
		SkdsPostSignResponse dsiresp = postJsonRequest(postreq,
				SkdsPostSignResponse.class);
		documents = dsiresp.documentsFromBase64();
		
		// take the updated documentDtos
		dto.setDocuments(documents);
	}

	@Override
	protected int currentStep() {
		return STEP_POSTSIGN;
	}
	
    /**
     * <p>Adds all the elements of the given arrays into a new array.</p>
     * <p>The new array contains all of the element of <code>array1</code> followed
     * by all of the elements <code>array2</code>. When an array is returned, it is always
     * a new array.</p>
     *
     * <pre>
     * ArrayUtils.addAll(array1, null)   = cloned copy of array1
     * ArrayUtils.addAll(null, array2)   = cloned copy of array2
     * ArrayUtils.addAll([], [])         = []
     * </pre>
     *
     * @param array1  the first array whose elements are added to the new array.
     * @param array2  the second array whose elements are added to the new array.
     * @return The new byte[] array.
     * @since 2.1
     */
    private byte[] addAll(byte[] array1, byte[] array2) {
        if (array1 == null) {
            return clone(array2);
        } else if (array2 == null) {
            return clone(array1);
        }
        byte[] joinedArray = new byte[array1.length + array2.length];
        System.arraycopy(array1, 0, joinedArray, 0, array1.length);
        System.arraycopy(array2, 0, joinedArray, array1.length, array2.length);
        return joinedArray;
    }
    
    /**
     * <p>Clones an array returning a typecast result and handling
     * <code>null</code>.</p>
     *
     * <p>This method returns <code>null</code> if <code>null</code> array input.</p>
     * 
     * @param array  the array to clone, may be <code>null</code>
     * @return the cloned array, <code>null</code> if <code>null</code> input
     */
    private byte[] clone(byte[] array) {
        if (array == null) {
            return null;
        }
        return (byte[]) array.clone();
    }
    
    /**
     * <p>Checks if an array of Objects is empty or <code>null</code>.</p>
     *
     * @param digitalSignature  the array to test
     * @return <code>true</code> if the array is empty or <code>null</code>
     * @since 2.1
     */
    public static boolean isEmpty(byte[] digitalSignature) {
        if (digitalSignature == null || digitalSignature.length == 0) {
            return true;
        }
        return false;
    }
}
