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
