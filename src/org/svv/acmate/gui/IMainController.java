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
package org.svv.acmate.gui;

public interface IMainController {
	
	public static final String STARTPANEL_EVENT_EXPORT_DOT = "_view_export_to_DOT";
	public static final String STARTPANEL_EVENT_INIT_CONFIG = "_view_init_config";
	public static final String STARTPANEL_EVENT_EXPORT_XINPUT = "_view_export_xinput";
	public static final String STARTPANEL_EVENT_APPLY_FILTERS = "_view_apply_fiters";
	public static final String STARTPANEL_EVENT_WORKINGDIR_CHANGED = "_view_workingdir_changed";

	
	public static final String ACTESTING_EVENT_STARTTEST = "_view_start_testing";
	public static final String ACTESTING_EVENT_LOAD_SESSIONS = "_view_load_sessions";
	public static final String ACTESTING_EVENT_SAVE_SESSIONS = "_view_save_sessions";
	public static final String ACTESTING_EVENT_CLEAR_SESSIONS = "_view_clear_sessions";;
	
	
	/**
	 * called when controller wants to update views
	 * 
	 * @param eventType
	 */
//	public void fireChange(String eventType);
	
	/**
	 * Called to handle event sent from view to controller
	 * @param eventType
	 */
	public void handleEvent(String eventType);

	/**
	 * handle event
	 * @param eventType
	 * @param option
	 * @return 0 if successful, -1 if failed
	 */
	public int handleEvent(String eventType, int option);
	
	
}
