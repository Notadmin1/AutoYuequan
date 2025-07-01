package burp;

import javax.swing.table.AbstractTableModel;
import java.io.PrintWriter;
import java.net.URL;
import java.util.List;

public class ParameterModelTabel extends AbstractTableModel {
    List<ParameterModel> Udatas;
   // private IExtensionHelpers helpers;
    //private IBurpExtenderCallbacks callbacks;
    //private PrintWriter stdout;



    public ParameterModelTabel(List<ParameterModel> Udatas) {
        //this.callbacks = callbacks;
        //this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.Udatas = Udatas;
        //this.helpers = callbacks.getHelpers();
    }


    @Override
    public int getRowCount() {
        return this.Udatas.size();
    }

    @Override
    public int getColumnCount() {
        return 6;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        ParameterModel datas = this.Udatas.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return Integer.valueOf(datas.Id);
            case 1:
                return datas.ParameterName;
            case 2:
                return datas.ParameterValue;
            case 3:
                return datas.ParameterType;
            case 4:
                return datas.domain;
            case 5:
                return datas.issue;
        }
        return null;
    }

    public String getColumnName(int columnIndex) {
        switch (columnIndex) {
            case 0:
                return "#";
            case 1:
                return "ParameterName";
            case 2:
                return "ParameterValue";
            case 3:
                return "ParameterType";
            case 4:
                return "domain";
            case 5:
                return "Issue";
        }
        return null;
    }

    private String getParameterTypeName(byte type) {
        switch (type) {
            case IParameter.PARAM_URL:
                return "URL参数";
            case IParameter.PARAM_BODY:
                return "请求体参数";
            case IParameter.PARAM_JSON:
                return "JSON参数";
            case IParameter.PARAM_XML:
                return "XML参数";
            case IParameter.PARAM_MULTIPART_ATTR:
                return "Multipart属性";
            case IParameter.PARAM_COOKIE:
                return "Cookie";
            default:
                return "未知类型(" + type + ")";
        }
    }

    public void addRow(IParameter parameter, String domain) {

        //callbacks.printOutput("发现参数:"+parameter.getName());


        synchronized (this.Udatas) {
            int row = this.Udatas.size();
            // 使用新的messageInfo对象创建TablesData
            this.Udatas.add(new ParameterModel(row, parameter.getName(), parameter.getValue(), getParameterTypeName(parameter.getType()), domain,"后续用于标注参数值"));
            fireTableRowsInserted(row, row);
        }

    }


    // 新增方法：设置底层数据列表
    public void setItems(List<ParameterModel> items) {
        this.Udatas = items;
        fireTableDataChanged();
    }


}
