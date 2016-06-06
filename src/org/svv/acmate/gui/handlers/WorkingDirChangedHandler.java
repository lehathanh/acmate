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
import java.io.File;

import org.svv.acmate.gui.IMainController;
import org.svv.acmate.model.TargetAppModel;
import org.svv.acmate.model.config.Configuration;
import org.svv.acmate.model.filters.Filters;
import org.svv.acmate.utils.FileUtil;
import org.svv.acmate.utils.JAXBUtil;

public class WorkingDirChangedHandler extends AbstractModelEventHandler {

	public WorkingDirChangedHandler(IMainController controller,
			TargetAppModel model, Component parent) {
		super(controller, model, parent);
	}
	

	@Override
	public void handle() {
		if (model.getWorkingDir() != null){
			String configFilePath = model.getWorkingDir() + File.separator + "config.xml";
			String filterFilePath = model.getWorkingDir() + File.separator + "filters.xml";
			
			if (FileUtil.isFileExist(configFilePath)){
				Configuration config = JAXBUtil.loadConfig(configFilePath);
				if (config != null){
					model.setConfigModel(config);
				}
			}

			if (FileUtil.isFileExist(filterFilePath)){
				Filters filters = JAXBUtil.loadFilters(filterFilePath);
				if (filters != null){
					model.setFilterModel(filters);
				}
			}
		}

	}

}
