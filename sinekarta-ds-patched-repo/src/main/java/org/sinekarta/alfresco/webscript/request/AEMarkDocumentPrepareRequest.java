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
package org.sinekarta.alfresco.webscript.request;

import java.io.IOException;
import java.io.InputStream;

import javax.xml.bind.JAXBException;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

import org.sinekarta.alfresco.webscript.GenericArea;

@XmlRootElement(name = "sinekarta")
@XmlAccessorType(XmlAccessType.FIELD)
public class AEMarkDocumentPrepareRequest extends GenericArea{

	private String markDocumentArea;
	
	private String markDescription;
	
	private String markFileName;

	private String nodeRef;

	public static AEMarkDocumentPrepareRequest fromXML(InputStream is) throws JAXBException {
		return (AEMarkDocumentPrepareRequest)GenericArea.fromXML(is, AEMarkDocumentPrepareRequest.class);
	}

	public static AEMarkDocumentPrepareRequest fromJSON(InputStream is) throws IOException {
		return (AEMarkDocumentPrepareRequest)GenericArea.fromJSON(is, AEMarkDocumentPrepareRequest.class);
	}

	public String getMarkDocumentArea() {
		return markDocumentArea;
	}

	public void setMarkDocumentArea(String markDocumentArea) {
		this.markDocumentArea = markDocumentArea;
	}

	public String getMarkDescription() {
		return markDescription;
	}

	public void setMarkDescription(String markDescription) {
		this.markDescription = markDescription;
	}

	public String getMarkFileName() {
		return markFileName;
	}

	public void setMarkFileName(String markFileName) {
		this.markFileName = markFileName;
	}

	public String getNodeRef() {
		return nodeRef;
	}

	public void setNodeRef(String nodeRef) {
		this.nodeRef = nodeRef;
	}

}
