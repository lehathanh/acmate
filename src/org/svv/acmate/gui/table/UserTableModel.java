package org.svv.acmate.gui.table;

import java.io.Serializable;
import java.util.List;
import java.util.Vector;

import javax.swing.table.AbstractTableModel;

import org.svv.acmate.model.config.User;

public class UserTableModel extends AbstractTableModel implements Serializable   {

	/**
	 * 
	 */
	private static final long serialVersionUID = 5542390897708378865L;
	
	protected List<User> data;
	protected Vector<String> columnIdentifiers;
	
	public UserTableModel(List<User> data) {
		this.data = data;
		columnIdentifiers = new Vector<String>();
		
		columnIdentifiers.add("UserName");
		columnIdentifiers.add("Password");
		columnIdentifiers.add("Role");
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
	public String getValueAt(int rowIndex, int columnIndex) {
		User v = data.get(rowIndex);
		if (columnIndex == 0)
			return v.getUsername();
		else if (columnIndex == 1)
			return v.getPassword();
		else if (columnIndex == 2){
			return v.getRole();
		}
			
		return "";
	}

	
	/**
	 * Add a new filter
	 * @param user
	 */
	public void addUser(User user){
		this.data.add(user);
		fireTableDataChanged();
	}
	
	/**
	 * Delete a filter
	 * @param rowIndex
	 */
	public void deleteUser(int rowIndex){
		this.data.remove(rowIndex);
		fireTableDataChanged();
	}
	
	/**
	 * get a particular filter
	 * @param rowIndex
	 * @return
	 */
	public User getRow(int rowIndex) {
		return data.get(rowIndex);
	}
	
}
