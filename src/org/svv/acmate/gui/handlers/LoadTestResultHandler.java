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
