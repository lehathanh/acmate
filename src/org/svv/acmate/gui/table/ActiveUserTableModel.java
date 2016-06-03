package org.svv.acmate.gui.table;

import java.io.Serializable;
import java.util.List;
import java.util.Map;
import java.util.Vector;

import javax.swing.table.AbstractTableModel;

import org.svv.acmate.model.TargetAppModel;
import org.svv.acmate.model.config.User;

public class ActiveUserTableModel extends AbstractTableModel implements Serializable, ITableSelection {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 6793960369926823419L;
	
	protected List<User> data;
	protected Map<User, Boolean> selectMap;
	protected Vector<String> columnIdentifiers;

	/**
	 * Constructor
	 * @param model
	 */
	public ActiveUserTableModel(TargetAppModel model) {
		this.data = model.getConfigModel().getUser();
		this.selectMap = model.getActiveUsers();
		
		columnIdentifiers = new Vector<String>();
		
		columnIdentifiers.add("User");
		columnIdentifiers.add("Selected");
	}
	
	
	@Override
	public String getColumnName(int column) {
		return columnIdentifiers.get(column);
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
	public Object getValueAt(int rowIndex, int columnIndex) {
		User v = data.get(rowIndex);
		if (columnIndex == 0)
			return v.getUsername();
		else if (columnIndex == 1){
			if (selectMap.get(v) == null){
				return new Boolean(false);
			} else {
				return selectMap.get(v);
			}
		}
		return "";
	}
	
	


	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		if (columnIndex == 1)
			return true;
		
		return false;
	}


	@Override
	public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
		User v = data.get(rowIndex);
		if (columnIndex == 1){
			if (selectMap.get(v) == null){
				selectMap.put(v, new Boolean(true));
			} else {
				if (aValue instanceof Boolean){
					selectMap.put(v, (Boolean) aValue);
				}
			}
		}
	}

	@Override
	public Class<?> getColumnClass(int columnIndex) {
		if (columnIndex == 0)
			return String.class;
		else 
			return Boolean.class;
	}


	@Override
	
	
	public void toggleSelection() {
		
		int numRow = getRowCount();
		boolean newVal = true;
		if (numRow > 0)
		{
			User v = data.get(0);
			if (selectMap.get(v) != null && selectMap.get(v).booleanValue()){
				newVal = false;
			}
		}
		
		for (int rowIndex = 0; rowIndex < numRow; rowIndex++){
			User v = data.get(rowIndex);
			if (newVal)
				selectMap.put(v, new Boolean(true));
			else 
				selectMap.put(v, new Boolean(false));
		}
		
		fireTableDataChanged();
	}

}
