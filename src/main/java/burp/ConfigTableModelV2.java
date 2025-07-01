package burp;

import javax.swing.table.AbstractTableModel;
import java.util.List;

public class ConfigTableModelV2 extends AbstractTableModel {
    private static List<ConfigTableItemV2> items;
    //private List<ConfigTableItemV2> items;

    public ConfigTableModelV2(List<ConfigTableItemV2> items) {
        this.items = items;
    }

    @Override
    public int getRowCount() {
        return items.size();
    }

    @Override
    public int getColumnCount() {
        return 5; // 根据 ConfigTableItem 的属性数量调整
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        ConfigTableItemV2 item = items.get(rowIndex);
        switch (columnIndex) {
            case 0: return item.isLoaded();
            case 1: return item.getName();
            case 2: return item.getposition();
            case 3: return item.getmethod();
            case 4: return item.getcontent();
            default: return null;
        }
    }

    @Override
    public String getColumnName(int column) {
        switch (column) {
            case 0: return "Loaded";
            case 1: return "Name";
            case 2: return "position";
            case 3: return "method";
            case 4: return "content";
            default: return "";
        }
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return false; // 根据需求调整是否可编辑
    }

    public void addRow(ConfigTableItemV2 item) {
        items.add(item);
        fireTableRowsInserted(items.size() - 1, items.size() - 1);
    }

    public void removeRow(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < items.size()) {
            items.remove(rowIndex);
            fireTableRowsDeleted(rowIndex, rowIndex);
        }
    }

    public void updateRow(int rowIndex, ConfigTableItemV2 item) {
        if (rowIndex >= 0 && rowIndex < items.size()) {
            items.set(rowIndex, item);
            fireTableRowsUpdated(rowIndex, rowIndex);
        }
    }

    // 新增方法：获取底层数据列表
    public static List<ConfigTableItemV2> getItems() {
        return items;
    }

    // 新增方法：设置底层数据列表
    public void setItems(List<ConfigTableItemV2> items) {
        this.items = items;
        fireTableDataChanged();
    }


    public boolean containsValue(int columnIndex, String value, boolean ignoreCase) {
        if (value == null || items == null) return false;

        for (ConfigTableItemV2 item : items) {
            Object cellValue = getValueAt(items.indexOf(item), columnIndex);
            if (cellValue != null) {
                String strValue = cellValue.toString();
                if (ignoreCase ? strValue.equalsIgnoreCase(value) : strValue.equals(value)) {
                    return true;
                }
            }
        }
        return false;
    }






}
