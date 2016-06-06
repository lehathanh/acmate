/*******************************************************************************
 * Copyright (c) 2016, SVV Lab, University of Luxembourg
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * 3. Neither the name of acmate nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *******************************************************************************/
package org.svv.acmate.gui.handlers;

import java.awt.Component;

import org.svv.acmate.burpsuite.SiteMap;
import org.svv.acmate.gui.IMainController;
import org.svv.acmate.model.TargetAppModel;

public class EventHandlerFactory {
	
	public static IEventHandler createHandler(String eventType, IMainController controller, TargetAppModel model, SiteMap siteMap, Component parent){
	
		if (IMainController.ACTESTING_EVENT_LOAD_SESSIONS.equals(eventType))
			return new LoadTestResultHandler(controller, model, parent);

		if (IMainController.ACTESTING_EVENT_CLEAR_SESSIONS.equals(eventType))
			return new ClearTestResultHandler(controller, model, parent);
	
		if (IMainController.ACTESTING_EVENT_SAVE_SESSIONS.equals(eventType))
			return new SaveTestResultHandler(controller, model, parent);
	
		if (IMainController.STARTPANEL_EVENT_INIT_CONFIG.equals(eventType))
			return new SaveConfigurationHandler(controller, model, parent);
	
		if (IMainController.STARTPANEL_EVENT_WORKINGDIR_CHANGED.equals(eventType))
			return new WorkingDirChangedHandler(controller, model, parent);
	
		if (IMainController.STARTPANEL_EVENT_EXPORT_DOT.equals(eventType))
			return new ExportToDotHandler(controller, model, siteMap, parent);
		
		if (IMainController.STARTPANEL_EVENT_APPLY_FILTERS.equals(eventType))
			return new ApplyFiltersHandler(controller, model, siteMap, parent);
	
		if (IMainController.STARTPANEL_EVENT_EXPORT_XINPUT.equals(eventType))
			return new MineDomainInputsHandler(controller, model, siteMap, parent);
		
		return null;
	}
}
