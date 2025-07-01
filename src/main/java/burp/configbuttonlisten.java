package burp;

import javax.swing.*;
import java.awt.*;

public class configbuttonlisten {
    void addRow(ConfigTableModelV2 tableModel) {
        JCheckBox loadedField = new JCheckBox(); // Loaded 字段使用复选框
        JTextField nameField = new JTextField();
        
        // positionField改为下拉框，选项为：参数名，参数值，返回body, cookies
        String[] positionOptions = {"参数名", "参数值", "返回body", "cookies","过滤参数名"};
        JComboBox<String> positionField = new JComboBox<>(positionOptions);
        
        // methodField改为下拉框，选项为：正则表达式，字符匹配
        String[] methodOptions = {"正则表达式", "字符匹配"};
        JComboBox<String> methodField = new JComboBox<>(methodOptions);
        
        JTextField contenttField = new JTextField();


        JPanel inputPanel = new JPanel(new GridLayout(0, 2)); // 0 表示行数不定，2 表示两列
        inputPanel.add(new JLabel("Loaded:"));
        inputPanel.add(loadedField);
        inputPanel.add(new JLabel("Name:"));
        inputPanel.add(nameField);
        inputPanel.add(new JLabel("position:"));
        inputPanel.add(positionField);
        inputPanel.add(new JLabel("method:"));
        inputPanel.add(methodField);
        inputPanel.add(new JLabel("content:"));
        inputPanel.add(contenttField);


        //String[] test = getHeaderValues();
        //.println(test[0]);

        int result = JOptionPane.showConfirmDialog(null, inputPanel, "Add New Row", JOptionPane.OK_CANCEL_OPTION);
        if (result == JOptionPane.OK_OPTION) {
            ConfigTableItemV2 newItem = new ConfigTableItemV2(
                    loadedField.isSelected(),
                    nameField.getText(),
                    // 修改为从下拉框获取选中值
                    (String) positionField.getSelectedItem(),
                    // 修改为从下拉框获取选中值
                    (String) methodField.getSelectedItem(),
                    contenttField.getText()
            );
            tableModel.addRow(newItem);
        }
    }
    // 编辑选中行的方法
    void editRow(ConfigTableModelV2 tableModel, JTable table) {
        int selectedRow = table.getSelectedRow();
        if (selectedRow != -1) {
            // 使用 ConfigTableModel 的 getItems() 方法获取完整的 ConfigTableItem 对象
            ConfigTableItemV2 selectedItem = tableModel.getItems().get(selectedRow);

            // 创建 JTextField 和 JCheckBox 并设置初始值
            JCheckBox loadedField = new JCheckBox();
            loadedField.setSelected(selectedItem.isLoaded());
            JTextField nameField = new JTextField(selectedItem.getName());
            
            // positionField改为下拉框，选项为：参数名，参数值，返回body, cookies
            String[] positionOptions = {"参数名", "参数值", "返回body", "cookies","过滤参数名"};
            JComboBox<String> positionField = new JComboBox<>(positionOptions);
            positionField.setSelectedItem(selectedItem.getposition());
            
            // methodField改为下拉框，选项为：正则表达式，字符匹配
            String[] methodOptions = {"正则表达式", "字符匹配"};
            JComboBox<String> methodField = new JComboBox<>(methodOptions);
            methodField.setSelectedItem(selectedItem.getmethod());
            
            JTextField contentField = new JTextField(selectedItem.getcontent());


            // 创建 JPanel 并设置布局
            JPanel inputPanel = new JPanel(new GridLayout(0, 2)); // 0 表示行数不定，2 表示两列
            inputPanel.add(new JLabel("Loaded:"));
            inputPanel.add(loadedField);
            inputPanel.add(new JLabel("Name:"));
            inputPanel.add(nameField);
            inputPanel.add(new JLabel("position:"));
            inputPanel.add(positionField);
            inputPanel.add(new JLabel("method:"));
            inputPanel.add(methodField);
            inputPanel.add(new JLabel("content:"));
            inputPanel.add(contentField);


            // 显示弹窗并获取用户选择
            int result = JOptionPane.showConfirmDialog(null, inputPanel, "Edit Row", JOptionPane.OK_CANCEL_OPTION);
            if (result == JOptionPane.OK_OPTION) {
                ConfigTableItemV2 updatedItem = new ConfigTableItemV2(
                        loadedField.isSelected(),
                        nameField.getText(),
                        // 修改为从下拉框获取选中值
                        (String) positionField.getSelectedItem(),
                        // 修改为从下拉框获取选中值
                        (String) methodField.getSelectedItem(),
                        contentField.getText()
                );
                tableModel.updateRow(selectedRow, updatedItem);
            }
        } else {
            JOptionPane.showMessageDialog(null, "Please select a row to edit.");
        }
    }

    // 删除选中行的方法
    void removeRow(ConfigTableModelV2 tableModel, JTable table) {
        int selectedRow = table.getSelectedRow();
        if (selectedRow != -1) {
            tableModel.removeRow(selectedRow);
        } else {
            JOptionPane.showMessageDialog(null, "Please select a row to delete.");
        }
    }
}