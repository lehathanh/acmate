package org.svv.acmate.gui.handlers;

import java.awt.Component;

import javax.swing.JOptionPane;

import org.svv.acmate.gui.IMainController;
import org.svv.acmate.gui.IModelListener;
import org.svv.acmate.model.TargetAppModel;

public class ClearTestResultHandler extends AbstractModelEventHandler {

	public ClearTestResultHandler(IMainController controller,
			TargetAppModel model, Component parent) {
		super(controller, model, parent);
	}
	

	@Override
	public void handle() {
		if (JOptionPane.showConfirmDialog(parent, "Clearing existing sessions?", "AC Testing", JOptionPane.YES_NO_OPTION)
				== JOptionPane.YES_OPTION){
			model.getExecutionResults().clear();
			model.modelChanged(IModelListener.EVENT_TESTRESULT_UPDATED);
		};

	}

}
