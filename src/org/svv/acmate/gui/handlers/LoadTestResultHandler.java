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
import java.util.List;

import javax.swing.JFileChooser;
import javax.swing.JOptionPane;

import org.svv.acmate.executor.Session;
import org.svv.acmate.gui.IMainController;
import org.svv.acmate.gui.IModelListener;
import org.svv.acmate.model.TargetAppModel;
import org.svv.acmate.utils.SessionUtil;

public class LoadTestResultHandler extends AbstractModelEventHandler{

	public LoadTestResultHandler(IMainController controller, TargetAppModel model,
			Component parent) {
		super(controller, model, parent);
	}

	@Override
	public void handle() {
		JFileChooser jFileChooser = new JFileChooser();
		if (model.getWorkingDir() != null)
			jFileChooser.setCurrentDirectory(new java.io.File(model.getWorkingDir()));
		else
			jFileChooser.setCurrentDirectory(new java.io.File("."));
    	jFileChooser.setDialogTitle("Choose a test result file");
    	jFileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
    	if (jFileChooser.showDialog(parent, "Load") 
    			== JFileChooser.APPROVE_OPTION){
    		File file = jFileChooser.getSelectedFile();
    		String filePath = file.getAbsolutePath();
    	
    		SessionUtil sUtil = new SessionUtil();
    		List<Session> sList = sUtil.loadTestResult(filePath, model);
    		if (sList == null){
    			JOptionPane.showMessageDialog(parent, "There was an error when loading test results!");
    		} else {
    			boolean updated = false;
    			for (Session s : sList){
    				if (!model.getExecutionResults().contains(s)){
    					model.getExecutionResults().add(s);
    					updated = true;
    				}
    			}
    			if (updated) {
    				model.modelChanged(IModelListener.EVENT_TESTRESULT_UPDATED);
    				JOptionPane.showMessageDialog(parent, "Test results loaded with success!");
    			} else {
    				JOptionPane.showMessageDialog(parent, "Nothing new to load!");
    			}
    		}
    	}

	}

}
