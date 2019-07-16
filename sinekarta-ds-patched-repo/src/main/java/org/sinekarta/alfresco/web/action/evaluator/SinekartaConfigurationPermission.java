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

import org.alfresco.repo.action.evaluator.ActionConditionEvaluatorAbstractBase;
import org.alfresco.service.ServiceRegistry;
import org.alfresco.service.cmr.action.ActionCondition;
import org.alfresco.service.cmr.action.ParameterDefinition;
import org.alfresco.service.cmr.repository.NodeRef;
import org.alfresco.service.cmr.repository.NodeService;
import org.alfresco.service.cmr.security.AccessStatus;
import org.alfresco.service.cmr.security.PermissionService;
//import org.alfresco.web.action.evaluator.BaseActionEvaluator;
//import org.alfresco.web.bean.repository.Node;
import org.apache.log4j.Logger;
import org.sinekarta.alfresco.model.SinekartaModel;
import org.sinekarta.alfresco.web.backing.SinekartaUtility;

/**
 * verifying document or folder that can have the configuration action enabled
 * 
 * @author andrea.tessaro
 *
 */
public class SinekartaConfigurationPermission extends ActionConditionEvaluatorAbstractBase{ //extends BaseActionEvaluator {

	private static final long serialVersionUID = 1L;
	
	// constants
	private static Logger tracer = Logger.getLogger(SinekartaConfigurationPermission.class);

	@Override
	//public boolean evaluate(Node node) {
	public boolean evaluate(ActionCondition actionCondition, NodeRef actionedUponNodeRef) {
		try {
			SinekartaUtility su = SinekartaUtility.getCurrentInstance();
			NodeService nodeService = su.getNodeService();
			// is the given node a sinekarta archive?
			//if (node.getType().equals(SinekartaModel.TYPE_QNAME_ARCHIVE)) {
			if (nodeService.getType(actionedUponNodeRef).equals(SinekartaModel.TYPE_QNAME_ARCHIVE)) {
				// in questo caso si pue' attivare l'icona della configurazione				
				PermissionService permissionService = su.getPermissionService();
				// then check permission of the given node
				//if (permissionService.hasPermission(node.getNodeRef(), SinekartaModel.PERMISSION_GROUP_SINEKARTA_RCS).compareTo(AccessStatus.ALLOWED)==0) {
				if (permissionService.hasPermission(actionedUponNodeRef, SinekartaModel.PERMISSION_GROUP_SINEKARTA_RCS).compareTo(AccessStatus.ALLOWED)==0) {
					return true;
				} else {
					return false;
				}
			} else { 
				return false;
			}
		} catch (Throwable t) {
			tracer.warn("Unable calculate SinekartaConfigurationPermission, have you added faces-config-sinekarta.xml in web.xml?",t);
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
