package org.svv.acmate.gui.table;

import java.io.Serializable;
import java.util.List;
import java.util.Map;
import java.util.Vector;

import javax.swing.table.AbstractTableModel;

import org.svv.acmate.burpsuite.SiteMap;

public class PageTableModel extends AbstractTableModel implements Serializable, ITableSelection   {
	
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	protected Vector<String> columnIdentifiers;
	List<String> data;
	Map<String, Boolean> selectedPaths;
	
	
	public PageTableModel(SiteMap siteMap) {
		
		this.data = siteMap.getPaths();
		this.selectedPaths = siteMap.getSelectedPaths();
		
		columnIdentifiers = new Vector<String>();
		columnIdentifiers.add("Selected");
		columnIdentifiers.add("URL");
		
		
	}

	@Override
	public int getRowCount() {
		return data.size();
	}

	@Override
	public int getColumnCount() {
		return columnIdentifiers.size();
	}
	
	

	@Override
	public String getColumnName(int column) {
		return columnIdentifiers.get(column);
	}
	
	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		String v = data.get(rowIndex);
		if (columnIndex == 1)
			return v;
		else if (columnIndex == 0){
			if (selectedPaths.get(v) == null){
				return new Boolean(false);
			} else {
				return selectedPaths.get(v);
			}
		}
		return "";
	}


	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		if (columnIndex == 0)
			return true;
		
		return false;
	}


	@Override
	public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
		String v = data.get(rowIndex);
		if (columnIndex == 0){
			if (selectedPaths.get(v) == null){
				selectedPaths.put(v, new Boolean(true));
			} else {
				if (aValue instanceof Boolean){
					selectedPaths.put(v, (Boolean) aValue);
				}
			}
		}
	}

	@Override
	public Class<?> getColumnClass(int columnIndex) {
		if (columnIndex == 0)
			return Boolean.class;
		else 
			return String.class;
	}

	@Override
	public void toggleSelection() {
		
		int numRow =  getRowCount();
		boolean newVal = true;
		if (numRow > 0){
			String v = data.get(0);
			if (selectedPaths.get(v) != null 
					&& selectedPaths.get(v).booleanValue()){
				newVal = false;
			}
		}
		
		for (int rowIndex = 0; rowIndex < getRowCount(); rowIndex++){
			String v = data.get(rowIndex);
			if (newVal)
				selectedPaths.put(v, new Boolean(true));
			else 
				selectedPaths.put(v, new Boolean(false));
		}
		
		fireTableDataChanged();
	}
	

}
