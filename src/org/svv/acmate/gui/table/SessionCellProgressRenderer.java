package org.svv.acmate.gui.table;

import java.awt.Component;

import javax.swing.BorderFactory;
import javax.swing.JProgressBar;
import javax.swing.JTable;
import javax.swing.table.DefaultTableCellRenderer;

public class SessionCellProgressRenderer extends DefaultTableCellRenderer {
	
	JProgressBar bar = new JProgressBar();
	int totalLoad;

	@Override
	public Component getTableCellRendererComponent(JTable table, Object value,
			boolean isSelected, boolean hasFocus, int row, int column) {
		Integer progress = (Integer) value;
        String text = "Completed";
        if (progress < 0) {
            text = "Error";
        } else if (progress <= totalLoad) {
            bar.setValue(progress);
            return bar;
        }
        super.getTableCellRendererComponent(table, text, isSelected, hasFocus, row, column);
        return this;
	}


	public SessionCellProgressRenderer() {
		setOpaque(true);
        bar.setBorder(BorderFactory.createEmptyBorder(1, 1, 1, 1));
	}

	
}
