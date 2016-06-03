package org.svv.acmate.gui;

import java.awt.HeadlessException;
import java.awt.datatransfer.DataFlavor;
import java.awt.dnd.DnDConstants;
import java.awt.dnd.DropTarget;
import java.awt.dnd.DropTargetDropEvent;
import java.io.File;
import java.util.List;

import javax.swing.JTextField;

public class DirDropTarget extends DropTarget {
	/**
	 * 
	 */
	private static final long serialVersionUID = 813869064470837705L;
	private JTextField targetField;

	@Override
	public synchronized void drop(DropTargetDropEvent dtde) {
		try {
			dtde.acceptDrop(DnDConstants.ACTION_COPY_OR_MOVE);
			List<File> droppedFiles = (List<File>) dtde.getTransferable()
					.getTransferData(DataFlavor.javaFileListFlavor);
			if (droppedFiles.size() > 0) {
				targetField.setText(droppedFiles.get(0).getAbsolutePath());
			}

		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	public DirDropTarget(JTextField targetField) throws HeadlessException {
		this.targetField = targetField;
	}
}
