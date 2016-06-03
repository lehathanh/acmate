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
