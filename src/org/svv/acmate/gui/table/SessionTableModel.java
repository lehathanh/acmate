package org.svv.acmate.gui.table;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Vector;

import javax.swing.table.AbstractTableModel;

import org.svv.acmate.executor.ISessionListener;
import org.svv.acmate.executor.Session;

public class SessionTableModel extends AbstractTableModel implements ISessionListener {
	
	protected List<Session> data;
	protected Map<Session, Integer> loadData;
	protected Map<Session, Integer> progressData;
	
	protected Vector<String> columnIdentifiers;
	
	public SessionTableModel(List<Session> sessions) {
		this.data = sessions;
		
		loadData = new HashMap<Session, Integer>();
		progressData = new HashMap<Session, Integer>();
		
		for (Session s: sessions){
			s.setListener(this);
		}
		
		columnIdentifiers = new Vector<String>();
		columnIdentifiers.add("Session");
		columnIdentifiers.add("Progress");
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
		Session s = data.get(rowIndex);
		if (columnIndex == 0) {
			return s.getCurrentUser().getUsername();
		} else if (columnIndex == 1){
			Integer pro = progressData.get(s);
			Integer load = loadData.get(s);
			if (pro != null && load != null)
				return pro.toString() + " / " + load.toString();
		}
		return "";
	}

	@Override
	public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
		super.setValueAt(aValue, rowIndex, columnIndex);
		
		if (columnIndex == 1){
			this.fireTableCellUpdated(rowIndex, columnIndex);
		}
	}

	@Override
	public void sessionStart(Session s, int load) {
		loadData.put(s, load);
	}

	@Override
	public void sessionDone(Session s) {
		Integer val = loadData.get(s);
		if (val != null)
			progressData.put(s, val); // 100%
		
		fireTableDataChanged();
	}

	@Override
	public void sessionProgress(Session s, int complete) {
//		Integer val = progressData.get(s);
//		if (val != null)
//			val = complete;
//		else 
		progressData.put(s, complete);
		
		fireTableDataChanged();
	}
	
	public void addSession(Session s){
		data.add(s);
		s.setListener(this);
	}
	
}
