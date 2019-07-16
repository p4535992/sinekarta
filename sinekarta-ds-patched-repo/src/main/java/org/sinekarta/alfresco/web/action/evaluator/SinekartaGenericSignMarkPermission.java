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
package org.sinekarta.alfresco.web.action.evaluator;

import java.util.List;

import org.alfresco.model.ContentModel;
import org.alfresco.repo.action.evaluator.ActionConditionEvaluatorAbstractBase;
import org.alfresco.service.ServiceRegistry;
import org.alfresco.service.cmr.action.ActionCondition;
import org.alfresco.service.cmr.action.ParameterDefinition;
import org.alfresco.service.cmr.dictionary.DictionaryService;
import org.alfresco.service.cmr.repository.NodeRef;
import org.alfresco.service.cmr.repository.NodeService;
//import org.alfresco.web.action.evaluator.BaseActionEvaluator;
//import org.alfresco.web.bean.repository.Node;
import org.apache.log4j.Logger;
import org.sinekarta.alfresco.model.SinekartaModel;
import org.sinekarta.alfresco.web.backing.SinekartaUtility;

/**
 * verifying document or folder that can have the generic sign action wizard enabled
 * 
 * @author andrea.tessaro
 *
 */
public class SinekartaGenericSignMarkPermission extends ActionConditionEvaluatorAbstractBase{// extends BaseActionEvaluator {

	private static final long serialVersionUID = 1L;
	
	// constants
	private static Logger tracer = Logger.getLogger(SinekartaGenericSignMarkPermission.class);

	@Override
	//public boolean evaluate(Node node) {
	public boolean evaluate(ActionCondition actionCondition, NodeRef actionedUponNodeRef) {
		try {
			SinekartaUtility su = SinekartaUtility.getCurrentInstance();
			NodeService nodeService = su.getNodeService();
			DictionaryService dictionaryService = su.getDictionaryService();
			// enabled if is a document (CONTENT), NOT a FOLDER,, has NOT documentAcquiring aspect and does not have rcssignature aspect
//			if (dictionaryService.isSubClass(node.getType(), ContentModel.TYPE_CONTENT) && 
//				!node.getType().equals(org.sinekarta.alfresco.model.SinekartaModel.TYPE_QNAME_ARCHIVE) &&
//				!node.hasAspect(SinekartaModel.ASPECT_QNAME_DOCUMENT_ACQUIRING) && 
//				!node.hasAspect(SinekartaModel.ASPECT_QNAME_TIMESTAMP_MARK)) {
//				return true;
//			}
			if (dictionaryService.isSubClass(nodeService.getType(actionedUponNodeRef), ContentModel.TYPE_CONTENT) && 
					!nodeService.getType(actionedUponNodeRef).equals(org.sinekarta.alfresco.model.SinekartaModel.TYPE_QNAME_ARCHIVE) &&
					!nodeService.hasAspect(actionedUponNodeRef,SinekartaModel.ASPECT_QNAME_DOCUMENT_ACQUIRING) && 
					!nodeService.hasAspect(actionedUponNodeRef,SinekartaModel.ASPECT_QNAME_TIMESTAMP_MARK)) {
					return true;
				}
			else return false;
		} catch (Throwable t) {
			tracer.warn("Unable calculate SinekartaSignMarkPermission, have you added faces-config-sinekarta.xml in web.xml?",t);
			return false;
		}
	}
	
	@Override
	protected boolean evaluateImpl(ActionCondition actionCondition, NodeRef actionedUponNodeRef) {
		return this.evaluate(actionCondition, actionedUponNodeRef);
	}

	@Override
	protected void addParameterDefinitions(List<ParameterDefinition> paramList) {

	}

}
