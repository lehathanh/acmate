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

import javax.swing.JOptionPane;

import org.svv.acmate.burpsuite.SiteMap;
import org.svv.acmate.gui.IMainController;
import org.svv.acmate.model.TargetAppModel;
import org.svv.acmate.utils.DOTUtil;
import org.svv.acmate.utils.FileUtil;

public class ExportToDotHandler extends AbstractSiteMapEventHandler {

	
	

	public ExportToDotHandler(IMainController controller, TargetAppModel model,
			SiteMap siteMap, Component parent) {
		super(controller, model, siteMap, parent);
	}

	@Override
	public void handle() {
		if (model.getWorkingDir() != null){
			String outputFilePath = model.getWorkingDir() + File.separator + "SiteMap.dot";
			
			boolean readyToExport = true;
			if (FileUtil.isFileExist(outputFilePath)){
				if (JOptionPane.showConfirmDialog(parent, 
						"SiteMap.dot file exists in the working folder. Overwrite? ",
						"Exporting to DOT", 
						JOptionPane.YES_NO_OPTION) != JOptionPane.YES_OPTION){
					readyToExport = false;
				}
					
			}
			if (readyToExport){
//				if (!siteMap.isUpdated()){
//					siteMap.populate(model.getRootRR());
//				}
//				
				DOTUtil dotUtil = new DOTUtil();
				dotUtil.export2DOT(outputFilePath, siteMap.getPathRequestsMap(), model.getConfigModel().getPageExtToExclude());
				JOptionPane.showMessageDialog(parent, "ACMate has finished exporting the site map to the working folder!");
			}
		}

	}

}
