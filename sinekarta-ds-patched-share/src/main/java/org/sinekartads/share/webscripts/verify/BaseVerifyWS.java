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
package org.sinekartads.share.webscripts.verify;

import org.sinekartads.dto.share.VerifyWizardDTO;
import org.sinekartads.share.webscripts.WSController;

public abstract class BaseVerifyWS extends WSController<VerifyWizardDTO> {

	public static final String[] WIZARD_FORMS = {
		"skdsVerifyInit", "skdsVerifyResult"
	};
	protected static final int STEP_INIT 	= 0;
	protected static final int STEP_RESULTS	= 1;
	
	protected String[] getWizardForms() {
		return WIZARD_FORMS;
	}
	
	@Override
	protected WizardStep[] getWizardSteps() {
		return new WizardStep[] { 
				new WizardStep("skdsVerifyInit",   "skdsVerifyInit"), 
				new WizardStep("skdsVerifyResult", "skdsVerifyResult") };
	}
}
