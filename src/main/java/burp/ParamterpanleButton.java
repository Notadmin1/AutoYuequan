package burp;

import javax.swing.*;
import java.util.ArrayList;

public class ParamterpanleButton {
    private final JTable parameterTable;
    private final ParameterModelTabel parameterModelTabel;
    private final ConfigTableModelV2 tableModel;

    public ParamterpanleButton(JTable parameterTable, ParameterModelTabel parameterModelTabel,ConfigTableModelV2 tableModel)
    {
        this.parameterTable = parameterTable;
        this.parameterModelTabel = parameterModelTabel;
        this.tableModel = tableModel;
    }


    public void addSelectedParamter() {
        //VulTableModel datas = null;
        //loadHeaderConfig();
        int[] selectedRows = parameterTable.getSelectedRows();
        if (selectedRows.length == 0) {
            //stdout.println("No URLs selected.");
            return;
        }

        for (int row : selectedRows) {
            ParameterModel dataEntry = parameterModelTabel.Udatas.get(row);
            //stdout.println("**********************************************************");
            ConfigTableItemV2 configTableItemV2 = new ConfigTableItemV2(true, dataEntry.ParameterName, "参数名", "字符匹配", dataEntry.ParameterName);
            //ConfigTableModelV2.getItems().add(configTableItemV2);

            if (!tableModel.containsValue(4, dataEntry.ParameterName, false)){
                tableModel.addRow(configTableItemV2);
            }

            //tableModel.addRow(configTableItemV2);
        }
    }



    public void addSelectedParamterExclude() {
        //VulTableModel datas = null;
        //loadHeaderConfig();
        int[] selectedRows = parameterTable.getSelectedRows();
        if (selectedRows.length == 0) {
            //stdout.println("No URLs selected.");
            return;
        }

        for (int row : selectedRows) {
            ParameterModel dataEntry = parameterModelTabel.Udatas.get(row);
            //stdout.println("**********************************************************");
            ConfigTableItemV2 configTableItemV2 = new ConfigTableItemV2(true, dataEntry.ParameterName, "过滤参数名", "字符匹配", dataEntry.ParameterName);
            //ConfigTableModelV2.getItems().add(configTableItemV2);

            if (!tableModel.containsValue(4, dataEntry.ParameterName, true)){
                tableModel.addRow(configTableItemV2);
            }

            //tableModel.addRow(configTableItemV2);
        }


    }



    public void clearTableModel() {
        // 直接替换为新的空列表
        parameterModelTabel.setItems(new ArrayList<ParameterModel>());
    }






}
