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
 * Part of this code come from 
 * FirmaPdf version 0.0.x Copyright (C) 2006 Antonino Iacono (ant_iacono@tin.it)
 * and Roberto Resoli
 * See method description for more details
 * 
 * Part of this code come from 
 * com.itextpdf.text.pdf.security.MakeSignature
 * Paulo Soares
 * 
 * See method description for more details
 * 
 */
package org.sinekartads.core.pdf;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.CharArrayWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Writer;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.HashMap;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSString;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentCatalog;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERGeneralString;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.sinekartads.model.domain.DigestInfo;
import org.sinekartads.model.domain.PDFSignatureInfo;
import org.sinekartads.model.domain.SecurityLevel;
import org.sinekartads.model.domain.SignDisposition;
import org.sinekartads.model.domain.SignatureType;
import org.sinekartads.model.domain.Transitions.ChainSignature;
import org.sinekartads.model.domain.Transitions.DigestSignature;
import org.sinekartads.model.domain.Transitions.FinalizedSignature;
import org.sinekartads.model.domain.Transitions.SignedSignature;
import org.sinekartads.model.domain.TsRequestInfo;

public class PDFToolsPdfBox {

	private static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PDFToolsPdfBox.class);

	public static final String PDF = ".pdf";

	public static FinalizedSignature<SignatureType.SignCategory,SignDisposition.PDF,SecurityLevel.VerifyResult,PDFSignatureInfo> 
	sign(SignedSignature<SignatureType.SignCategory,SignDisposition.PDF,SecurityLevel.VerifyResult,PDFSignatureInfo > signedSignature,		
			InputStream is,OutputStream os ) throws SignatureException {

		try {
			PDFSignatureInfo signature = (PDFSignatureInfo) signedSignature;
			TSAClient tsaClient=null;

			TsRequestInfo tsRequest = signature.getTsRequest(); 
			if (tsRequest!=null && StringUtils.isNotBlank(tsRequest.getTsUrl())) {
				tsaClient = new TSAClient(new URL(tsRequest.getTsUrl()), tsRequest.getTsUsername(), tsRequest.getTsPassword(),MessageDigest.getInstance("SHA-256"));
			}
			int estimatedSize=0;
			//CryptoStandard sigtype = CryptoStandard.CMS;

			// creo il reader del pdf
			PDDocument doc = loadPdfBoxDocument(is);

			// creo lo stamper (se il pdf e' gia' firmato, controfirma, altrimenti firma
			
			// questo e' il certificato su cui lavorare
			Certificate[] chain = signature.getRawX509Certificates();

			// inizio codice copiato da MakeSignature
			if (estimatedSize == 0) {
				estimatedSize = 8192;
				estimatedSize += 4192;
				estimatedSize += 4192;
			}
			//https://stackoverflow.com/questions/30549830/attachment-damages-signature-part-2
			doc.getDocument().getTrailer().removeItem(COSName.TYPE); 
			SignatureInterface signatureInterface = new SignatureInterface() {
				@Override
				public byte[] sign(InputStream content) throws IOException {
					return null;
				}
			};
			PDSignature signaturePdfBox = new PDSignature();
			signaturePdfBox.setFilter(PDSignature.FILTER_ADOBE_PPKLITE); // default filter
			//if(StringUtils.isNotBlank(signature.getSubfilter())){
			//	signaturePdfBox.setSubFilter(signature.getSubfilter());
			//}else{
				signaturePdfBox.setSubFilter(PDSignature.SUBFILTER_ETSI_CADES_DETACHED);
			//}
	
			if (StringUtils.isNotBlank(signature.getRevision())) {
				signaturePdfBox.setContactInfo(signature.getRevision());
			}
			if (StringUtils.isNotBlank(signature.getLocation())) {
				signaturePdfBox.setLocation(signature.getLocation());
			}
			if (StringUtils.isNotBlank(signature.getReason())) {
				signaturePdfBox.setReason(signature.getReason());
			}
			if (StringUtils.isNotBlank(signature.getName())) {
				signaturePdfBox.setName(signature.getName());
			}   
			if(signature.getSigningTime()!=null){
				SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
				Calendar cal = Calendar.getInstance();
				cal.setTime(sdf.parse(sdf.format(signature.getSigningTime())));
				signaturePdfBox.setSignDate(cal);	
			}
			boolean isExternalSigning = false;
			if (isExternalSigning)
			{
				//do nothing
			}
			else
			{
				SignatureOptions signatureOptions = new SignatureOptions();
				signatureOptions.setPreferedSignatureSize(estimatedSize);  //TODO dovrebbe bastare il doppio ma con itest si e' arrivati a x20 => Caused by: java.io.IOException: Can't write signature, not enough space
				doc.addSignature(signaturePdfBox,signatureInterface,signatureOptions);	
				//if(signature.getFileId() !=null){
				//	doc.setDocumentId(signature.get);		    
				//}else{
					doc.setDocumentId(0L);
				//}
				doc.saveIncremental(is,os);
			}			
			return signature.finalizeSignature();
		} catch (Exception e) {
			logger.error("Unable to sign PDF.", e);
			throw new SignatureException("Unable to sign PDF.", e);
		}

	}
	
	public static DigestSignature<SignatureType.SignCategory,SignDisposition.PDF,SecurityLevel.VerifyResult,PDFSignatureInfo > 
	calculateFingerPrint ( ChainSignature < SignatureType.SignCategory,SignDisposition.PDF,SecurityLevel.VerifyResult,PDFSignatureInfo > chainSignature,																		  
			InputStream is) throws SignatureException {
		try {		
			int estimatedSize=0;		
			PDFSignatureInfo signature = (PDFSignatureInfo) chainSignature;
			Certificate[] chain = signature.getRawX509Certificates();

			if (estimatedSize == 0) {
				estimatedSize = 8192;
				estimatedSize += 4192;
				estimatedSize += 4192;
			}
			Calendar now = Calendar.getInstance();			
			signature.setSigningTime(now.getTime());
			signature.setUnicodeModDate(now.toString());
			
			//CALCOLO DELL'HASH DA FIRMARE
			
			PDDocument doc = loadPdfBoxDocument(is);
	
			// create signature dictionary
			PDSignature signaturePdfBox = new PDSignature();
			signaturePdfBox.setFilter(PDSignature.FILTER_ADOBE_PPKLITE); // default filter
			// subfilter for basic and PAdES Part 2 signatures
			//Utile link https://stackoverflow.com/questions/25957573/unable-to-verify-digital-signature-using-apache-pdfbox
			//signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
			signaturePdfBox.setSubFilter(PDSignature.SUBFILTER_ETSI_CADES_DETACHED);

			if (StringUtils.isNotBlank(signature.getRevision())) {
				signaturePdfBox.setContactInfo(signature.getRevision());
			}
			if (StringUtils.isNotBlank(signature.getLocation())) {
				signaturePdfBox.setLocation(signature.getLocation());
			}
			if (StringUtils.isNotBlank(signature.getReason())) {
				signaturePdfBox.setReason(signature.getReason());
			}
			if (StringUtils.isNotBlank(signature.getName())) {
				signaturePdfBox.setName(signature.getName());
			}   
			if(signature.getSigningTime()!=null){
				SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
				Calendar cal = Calendar.getInstance();
				cal.setTime(sdf.parse(sdf.format(signature.getSigningTime())));
				signaturePdfBox.setSignDate(cal);	
			}
			// register signature dictionary and sign interface		
			final ByteArrayOutputStream fingerPrint = new ByteArrayOutputStream();
			final MessageDigest digest = MessageDigest.getInstance("SHA-256");		    
			SignatureInterface signatureInterface = new SignatureInterface() {
				@Override
				public byte[] sign(InputStream content) throws IOException {					
					byte[] imp = digest.digest(IOUtils.toByteArray(content));
					IOUtils.copy(new ByteArrayInputStream(imp),fingerPrint);						
					return fingerPrint.toByteArray();
				}
			};
			// register signature dictionary and sign interface
			SignatureOptions signatureOptions = new SignatureOptions();
			// Size can vary, but should be enough for purpose.
			signatureOptions.setPreferedSignatureSize(estimatedSize);  
			doc.addSignature(signaturePdfBox, signatureInterface,signatureOptions);
			//doc.addSignature(signature, signatureInterface);
			//if(revisionId !=null){
			//	doc.setDocumentId(revisionId);		    
			//}else{
				doc.setDocumentId(0L);
			//}
			// write incremental (only for signing purpose)
			ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
			doc.saveIncremental(is,byteArrayOutputStream);

			// calcolo dell'impronta
			//MessageDigest digester = MessageDigest.getInstance(signature.getDigestAlgorithm().getName());
			//byte[] fingerPrint = digester.digest(authenticatedAttributeBytes);
			
			//signature.setAuthenticatedAttributeBytes(authenticatedAttributeBytes);
			//signature.setFileId(signaturePdfBox.get.getFileId());			
			//signature.setUnicodeModDate(sap.getStamper().getUnicodeModDate());			
			signature.setSigningTime(now.getTime());
			try {
				is.close();
			} catch (IOException e) {
				logger.error("error on input stream", e);
			}

			return signature.toDigestSignature(DigestInfo.getInstance(signature.getDigestAlgorithm(), fingerPrint.toByteArray()) );
		} catch (Exception e) {
			logger.error("Unable to calculate finger print of PDF.", e);
			throw new SignatureException("Unable calculate finger print of PDF.", e);
		}
	}


	public static boolean isPdfSigned(PDDocument reader) throws SignatureException {
		try {
			return isPdfSignedByPdfBox(reader);
		} catch (CertificateException | IOException e) {
			throw new SignatureException(e);
		}
	}
	
	public static boolean isPdfSigned(InputStream is) throws SignatureException {
		try {
			return isPdfSignedByPdfBox(is);
		} catch (CertificateException | IOException e) {
			throw new SignatureException(e);
		}
	}

	/**
	 * Metodo per verificare se un file pdf e' firmato secondo la libreria pdfbox
	 * @param file
	 * @return
	 * @throws IOException
	 * @throws CertificateException
	 */
	public static boolean isPdfSignedByPdfBox(File file) throws IOException, CertificateException {
		PDDocument pdfDocument = loadPdfBoxDocument((new FileInputStream(file)));
		try{
			return isPdfSignedByPdfBox(pdfDocument);
		}finally{
			pdfDocument.close();
		}	
	}

	/**
	 * Metodo per verificare se un file pdf e' firmato secondo la libreria pdfbox
	 * @param isTmp
	 * @return
	 * @throws IOException
	 * @throws CertificateException
	 */
	public static boolean isPdfSignedByPdfBox(InputStream isTmp) throws IOException, CertificateException {
		PDDocument pdfDocument = loadPdfBoxDocument((isTmp));
		try{
			return isPdfSignedByPdfBox(pdfDocument);
		}finally{
			pdfDocument.close();
		}	
	}

	/**
	 * Metodo per verificare se un file pdf e' firmato secondo la libreria pdfbox
	 * @param isTmp lo inputstream del file
	 * @return true se il file e' firmato secondo pdfbox altrimenti false
	 * @throws CertificateException 
	 * @throws Exception se qualsiasi errore occorre
	 */
	public static boolean isPdfSignedByPdfBox(PDDocument document) throws IOException, CertificateException {
		boolean isSigned = false;

		PDDocumentCatalog catalog = document.getDocumentCatalog(); 
		PDAcroForm acroform = catalog.getAcroForm(); 
		if(document.isEncrypted() )
		{
			logger.warn("Document is encrypted." );
			return false;
		}
		//Verifica la presenza di qualche firma anche se sconosciuta
		if(document.getSignatureDictionaries()!=null && document.getSignatureDictionaries().size()>0){
			COSDictionary trailer = document.getDocument().getTrailer();
			COSDictionary root = (COSDictionary)trailer.getDictionaryObject(COSName.ROOT );                
			COSDictionary acroForm = (COSDictionary)root.getDictionaryObject(COSName.ACRO_FORM );
			//Verifica la presenza di un acroform almeno per le linee standard
			//e un campo la cui presenza e' obbligatoria al'interno del file pdf firmato
			if(acroform != null){
				COSArray fields = (COSArray)acroForm.getDictionaryObject(COSName.FIELDS);
				for( int i=0; i<fields.size(); i++ )
				{
					COSDictionary field = (COSDictionary)fields.getObject( i );
					String type = field.getNameAsString("FT");
					if("Sig".equals(type))
					{
						COSDictionary cert = (COSDictionary)field.getDictionaryObject( COSName.V );
						if( cert != null )
						{
							logger.debug( "Certificate found" );
							logger.debug( "Name=" + cert.getDictionaryObject(COSName.NAME) );
							logger.debug( "Modified=" + cert.getDictionaryObject( COSName.getPDFName("M") ) );
							COSName subFilter = (COSName)cert.getDictionaryObject( COSName.getPDFName("SubFilter"));
							if( subFilter != null )
							{
								if( subFilter.getName().equals("adbe.x509.rsa_sha1"))
								{
									COSString certString = (COSString)cert.getDictionaryObject(COSName.getPDFName("Cert"));
									byte[] certData = certString.getBytes();
									CertificateFactory factory = CertificateFactory.getInstance("X.509");
									ByteArrayInputStream certStream = new ByteArrayInputStream(certData);
									Collection<? extends Certificate> certs = (Collection<? extends Certificate>) factory.generateCertificates( certStream );
									logger.debug( "certs=" + certs );
									isSigned = true;
								}
								else if( subFilter.getName().equals("adbe.pkcs7.sha1") )
								{
									COSString certString = (COSString)cert.getDictionaryObject(COSName.CONTENTS);
									byte[] certData = certString.getBytes();
									CertificateFactory factory = CertificateFactory.getInstance("X.509");
									ByteArrayInputStream certStream = new ByteArrayInputStream( certData );
									Collection<? extends Certificate> certs = (Collection<? extends Certificate>) factory.generateCertificates( certStream );
									logger.debug( "certs=" + certs );
									isSigned = true;
								}
								else
								{
									logger.warn("Unknown certificate type:" + subFilter);
									isSigned = true;
								}
							}
							else
							{
								throw new IOException( "Missing subfilter for cert dictionary" );
							}
						}
						else
						{
							logger.warn( "Signature found, but no certificate" );
							isSigned = true;
						}
					}
				}
			}
		}else{
			logger.warn("AcroForm di PDFBOX e' NULL o the SignatureDictionaries is EMPTY");
		}

		return isSigned;		
	}

	/**
	 * Metodo che carica un pdf con la libraria pdfbox tenendno conto di errori noti
	 * NOTA: PDFBOX 1.8.4, 2.0.0 ha gia' risolto il bug
	 * @param is
	 * @return
	 * @throws IOException
	 */
	public static PDDocument loadPdfBoxDocument(File filePdf) throws IOException{
		return loadPdfBoxDocument(new FileInputStream(filePdf));
	}

	/**
	 * Metodo che carica un pdf con la libraria pdfbox tenendno conto di errori noti
	 * NOTA: PDFBOX 1.8.4, 2.0.0  ha gia' risolto il bug
	 * @param is
	 * @return
	 * @throws IOException
	 */
	public static PDDocument loadPdfBoxDocument(InputStream is) throws IOException{
		//RIUSARE LO STESSO INPUTSTREAM PIU' VOLTE
		//		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		//		byte[] buf = new byte[1024];
		//		int n = 0;
		//		while ((n = is.read(buf)) >= 0)
		//			baos.write(buf, 0, n);
		//		byte[] content = baos.toByteArray();		
		byte[] content = IOUtils.toByteArray(is);
		PDDocument pdDoc = null;
		try{
			pdDoc = PDDocument.load(new ByteArrayInputStream(content)); 		
			return pdDoc;
		}catch(IOException ex){
			/*
			if(ex.getMessage().contains("expected='endstream'")){
				//https://issues.apache.org/jira/browse/PDFBOX-1541
				//https://www.programcreek.com/java-api-examples/?code=jmrozanec/pdf-converter/pdf-converter-master/src/main/java/pdf/converter/txt/TxtCreator.java				
				File tmpfile = File.createTempFile(String.format("txttmp-%s", UUID.randomUUID().toString()), null);
	            try{
					org.apache.pdfbox.io.RandomAccessFile raf = new org.apache.pdfbox.io.RandomAccessFile(tmpfile, "rw");
		            pdDoc = PDDocument.loadNonSeq(new ByteArrayInputStream(content),raf);	
		            return pdDoc;
	            }finally{
	            	FileUtils.deleteQuietly(tmpfile);
	            }
			}else{
				throw ex;
			}
			 */
			throw ex;
		}
	}
}
