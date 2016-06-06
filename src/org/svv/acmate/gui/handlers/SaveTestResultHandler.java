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

import javax.swing.JFileChooser;
import javax.swing.JOptionPane;

import org.svv.acmate.gui.IMainController;
import org.svv.acmate.model.TargetAppModel;
import org.svv.acmate.utils.SessionUtil;

public class SaveTestResultHandler extends AbstractModelEventHandler {

	public SaveTestResultHandler(IMainController controller, TargetAppModel model,
			Component parent) {
		super(controller, model, parent);
		// TODO Auto-generated constructor stub
	}

	@Override
	public void handle() {
		JFileChooser jFileChooser = new JFileChooser();
		if (model.getWorkingDir() != null)
			jFileChooser.setCurrentDirectory(new java.io.File(model.getWorkingDir()));
		else
			jFileChooser.setCurrentDirectory(new java.io.File("."));
    	jFileChooser.setDialogTitle("Choose a target to save test result");
    	jFileChooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
    	if (jFileChooser.showDialog(parent, "Save") 
    			== JFileChooser.APPROVE_OPTION){
    		File dirOrFile = jFileChooser.getSelectedFile();
    		String filePath = dirOrFile.getAbsolutePath();
    		if (dirOrFile.isDirectory()){
    			filePath = filePath + File.separator + "test-results.xml";
    		}
    		
    		SessionUtil sUtil = new SessionUtil();
    		boolean ret = sUtil.saveTestResult(model.getExecutionResults(), filePath);
    		if (ret){
    			JOptionPane.showMessageDialog(parent, "Test results successfully saved!");
    		} else {
    			JOptionPane.showMessageDialog(parent, "There was an error when saving test results!");
    		}
    	}
	}

}
