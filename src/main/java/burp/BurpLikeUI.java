package burp;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableColumnModel;
import java.awt.*;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.List;

import org.json.JSONArray;
import org.json.JSONObject;

public class BurpLikeUI extends JFrame implements ITab,IMessageEditorController  {
    private static final String CONFIG_FILE_PATH = "E:\\burp2021\\burp2021\\config_data.json"; // 定义配置文件路径
    private IBurpExtenderCallbacks callbacks;
    private JTabbedPane tabbedPane;
    private IMessageEditor OriginalRequestTextEditor;
    private IMessageEditor HRequestTextEditor;
    private IMessageEditor NoAuthHRequestTextEditor;
    private IMessageEditor OriginalResponseTextEditor;
    private IMessageEditor HResponseTextEditor;
    private IMessageEditor NoAuthHResponseTextEditor;
    private VulTable tableMobles;
    private IHttpRequestResponse currentlyDisplayedItem;
    List<VulTableModel> Udatas;
    private Vultableextend Vtable;

    private JTextArea newHeaderField = new JTextArea(3, 150);;
    private JTextArea lowHeaderField = new JTextArea(3, 150);
    JTextArea urlpeizhiField = new JTextArea(1, 150);



    List<ConfigTableItemV2> configitems = new ArrayList<>();
    ConfigTableModelV2 configtableModel = new ConfigTableModelV2(configitems);
    JTable configtable = new JTable(configtableModel);


    List<ParameterModel> ParameterModels = new ArrayList<>();
    ParameterModelTabel parameterModelTabel = new ParameterModelTabel(ParameterModels);
    JTable parameterTable = new JTable(parameterModelTabel);






    public BurpLikeUI(IBurpExtenderCallbacks callbacks, List<VulTableModel> Udatas) {
        this.callbacks = callbacks;
        this.Udatas = Udatas;
        this.tableMobles = new VulTable(callbacks,Udatas);
        //List<ConfigTableItemV2> configitems = new ArrayList<>();
        //ConfigTableModelV2 configtableModel = new ConfigTableModelV2(configitems);
        //JTable configtable = new JTable(configtableModel);
        initializeComponents();
    }

    public VulTable getVulTable() {
        return tableMobles;
    }

    private void initializeComponents() {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {

                //mjPane = new JPanel(new BorderLayout());
                tabbedPane = new JTabbedPane();
                tabbedPane.addTab("VulDisplay", createVulDisplayPanel());
                tabbedPane.addTab("Config", createConfigPanel());
                tabbedPane.addTab("parameterCollect", createparameterCollect());

                //mjPane.add(tabbedPane);

                callbacks.customizeUiComponent(tabbedPane);
                //callbacks.customizeUiComponent(mjPane);
                callbacks.addSuiteTab(BurpLikeUI.this);

                // 加载配置数据
                loadConfigData();

                // 添加窗口关闭监听器
                addWindowListener(new java.awt.event.WindowAdapter() {
                    @Override
                    public void windowClosing(java.awt.event.WindowEvent windowEvent) {
                        saveConfigData(); // 窗口关闭时保存数据
                    }
                });
            }
        });
    }


    JPanel createparameterCollect(){
        JPanel parameterpanel = new JPanel(new BorderLayout());

        //List<ConfigTableItemV2> configitems = new ArrayList<>();
        //ConfigTableModelV2 configtableModel = new ConfigTableModelV2(configitems);
        //JTable configtable = new JTable(configtableModel);

        //List<ParameterModel> ParameterModels = new ArrayList<>();
        //ParameterModelTabel parameterModelTabel = new ParameterModelTabel(callbacks,ParameterModels);
        //JTable parameterTable = new JTable(parameterModelTabel);

        ParamterpanleButton paramterpanleButton = new ParamterpanleButton(parameterTable,parameterModelTabel,configtableModel);

        JScrollPane tableScrollPane = new JScrollPane(parameterTable);


        // 创建按钮面板
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 5));
        JButton addRuleButton = new JButton("添加参数规则");
        addRuleButton.addActionListener(e -> paramterpanleButton.addSelectedParamter());
        JButton addExclueButton = new JButton("排除参数规则");
        addExclueButton.addActionListener(e -> paramterpanleButton.addSelectedParamterExclude());
        //JButton removeButton = new JButton("Clear Responses");

        JButton ClearParButton = new JButton("清空参数");
        ClearParButton.addActionListener(e -> paramterpanleButton.clearTableModel());

        buttonPanel.add(addRuleButton);
        buttonPanel.add(addExclueButton);
        buttonPanel.add(ClearParButton);


        parameterpanel.add(tableScrollPane, BorderLayout.CENTER);
        parameterpanel.add(buttonPanel, BorderLayout.SOUTH);

        return parameterpanel;




    }


    // 新增：加载配置数据的方法
    private void loadConfigDataV2() {
        // 获取 pathField 的值作为配置文件路径
        String configPath = getConfigFilePath();
        try {
            File configFile = new File(configPath);
            if (configFile.exists()) {
                String content = new String(Files.readAllBytes(configFile.toPath()));
                JSONArray jsonArray = new JSONArray(content);
                List<ConfigTableItem> items = new ArrayList<>();
                for (int i = 0; i < jsonArray.length(); i++) {
                    JSONObject jsonObject = jsonArray.getJSONObject(i);
                    ConfigTableItem item = new ConfigTableItem(
                            jsonObject.getBoolean("loaded"),
                            jsonObject.getString("name"),
                            jsonObject.getString("fRegex"),
                            jsonObject.getString("sRegex"),
                            jsonObject.getString("format"),
                            jsonObject.getString("color"),
                            jsonObject.getString("scope"),
                            jsonObject.getString("engine"),
                            jsonObject.getBoolean("sensitive")
                    );
                    items.add(item);
                }

                // 更新表格模型
                Component configComponent = tabbedPane.getComponentAt(1);
                if (configComponent instanceof JPanel) {
                    JPanel configPanel = (JPanel) configComponent;
                    JScrollPane scrollPane = null;
                    JTable table = null;

                    // 遍历子组件以找到嵌套的 JScrollPane 和 JTable
                    for (Component child : configPanel.getComponents()) {
                        if (child instanceof JScrollPane) {
                            scrollPane = (JScrollPane) child;
                            table = (JTable) scrollPane.getViewport().getView();
                            break; // 找到后退出循环
                        }
                    }

                    if (scrollPane != null && table != null) {
                        ConfigTableModel tableModel = (ConfigTableModel) table.getModel();
                        tableModel.setItems(items); // 假设 ConfigTableModel 提供了 setItems 方法
                    } else {
                        throw new RuntimeException("Failed to find JScrollPane or JTable in Config panel.");
                    }
                } else {
                    throw new RuntimeException("Unexpected component type in Config panel.");
                }
            }
        } catch (Exception e) {
            callbacks.printError("Failed to load config data: " + e.getMessage());
        }
    }

    // 新增：加载配置数据的方法
    private void loadConfigData() {
        // 获取 pathField 的值作为配置文件路径
        String configPath = getConfigFilePath();
        try {
            File configFile = new File(configPath);
            if (configFile.exists()) {
                String content = new String(Files.readAllBytes(configFile.toPath()));
                JSONArray jsonArray = new JSONArray(content);
                List<ConfigTableItemV2> items = new ArrayList<>();
                for (int i = 0; i < jsonArray.length(); i++) {
                    JSONObject jsonObject = jsonArray.getJSONObject(i);
                    ConfigTableItemV2 item = new ConfigTableItemV2(
                            jsonObject.getBoolean("loaded"),
                            jsonObject.getString("name"),
                            jsonObject.getString("position"),
                            jsonObject.getString("method"),
                            jsonObject.getString("content")
                    );
                    items.add(item);
                }

                //ConfigTableModelV2 tableModel = configtable.getModel();
                //tableModel.setItems(items);

                configtableModel.setItems(items);
            }
        } catch (Exception e) {
            callbacks.printError("Failed to load config data: " + e.getMessage());
        }
    }

    // 新增：保存配置数据的方法
    private void saveConfigData() {
        // 获取 pathField 的值作为配置文件路径
        String configPath = getConfigFilePath();
        try {
            List<ConfigTableItemV2> items = ConfigTableModelV2.getItems();
            JSONArray jsonArray = new JSONArray();
            for (ConfigTableItemV2 item : items) {
                JSONObject jsonObject = new JSONObject();
                jsonObject.put("loaded", item.isLoaded());
                jsonObject.put("name", item.getName());
                jsonObject.put("position", item.getposition());
                jsonObject.put("method", item.getmethod());
                jsonObject.put("content", item.getcontent());
                jsonArray.put(jsonObject);
            }
            Files.write(Paths.get(configPath), jsonArray.toString(4).getBytes());

            // 新增：保存成功后弹出提示框
            JOptionPane.showMessageDialog(null, "保存成功", "提示", JOptionPane.INFORMATION_MESSAGE);
            return; // 成功保存后退出方法
        } catch (Exception e) {
            callbacks.printError("Failed to save config data: " + e.getMessage());
        }
    }

    private void saveConfigDataV2() {
        // 获取 pathField 的值作为配置文件路径
        String configPath = getConfigFilePath();
        try {
            // 获取 Config 标签页的组件
            Component configComponent = tabbedPane.getComponentAt(1);
            if (configComponent instanceof JPanel) {
                JPanel configPanel = (JPanel) configComponent;
                for (Component child : configPanel.getComponents()) {
                    if (child instanceof JScrollPane) {
                        JScrollPane scrollPane = (JScrollPane) child;
                        JTable table = (JTable) scrollPane.getViewport().getView();
                        ConfigTableModel tableModel = (ConfigTableModel) table.getModel();

                        // 获取数据并保存
                        List<ConfigTableItem> items = tableModel.getItems();
                        JSONArray jsonArray = new JSONArray();
                        for (ConfigTableItem item : items) {
                            JSONObject jsonObject = new JSONObject();
                            jsonObject.put("loaded", item.isLoaded());
                            jsonObject.put("name", item.getName());
                            jsonObject.put("fRegex", item.getfRegex());
                            jsonObject.put("sRegex", item.getsRegex());
                            jsonObject.put("format", item.getFormat());
                            jsonObject.put("color", item.getColor());
                            jsonObject.put("scope", item.getScope());
                            jsonObject.put("engine", item.getEngine());
                            jsonObject.put("sensitive", item.isSensitive());
                            jsonArray.put(jsonObject);
                        }
                        Files.write(Paths.get(configPath), jsonArray.toString(4).getBytes());

                        // 新增：保存成功后弹出提示框
                        JOptionPane.showMessageDialog(null, "保存成功", "提示", JOptionPane.INFORMATION_MESSAGE);
                        return; // 成功保存后退出方法
                    }
                }
            }
            throw new RuntimeException("Failed to find JScrollPane in Config panel.");
        } catch (Exception e) {
            callbacks.printError("Failed to save config data: " + e.getMessage());
        }
    }





    // 新增：获取 pathField 值的方法
    private String getConfigFilePath() {
        Component configComponent = tabbedPane.getComponentAt(1);
        if (configComponent instanceof JPanel) {
            JPanel configPanel = (JPanel) configComponent;
            for (Component child : configPanel.getComponents()) {
                if (child instanceof JPanel) {
                    JPanel subPanel = (JPanel) child;
                    for (Component subChild : subPanel.getComponents()) {
                        if (subChild instanceof JTextField) {
                            JTextField pathField = (JTextField) subChild;
                            return pathField.getText();
                        }
                    }
                }
            }
        }
        return CONFIG_FILE_PATH; // 默认路径
    }

    private JPanel createVulDisplayPanel() {

        JSplitPane mjSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

        JPanel panel = new JPanel(new BorderLayout());

        // 创建表格
        //String[] columnNames = {"#", "VulName", "Method", "Url", "Status", "Info", "Size", "startTime", "endTime"};
        //Object[][] data = {}; // 初始数据为空
        //JTable table = new JTable(data, columnNames);
        JPanel splitPane = createRequestResponseSplitPane();


        //tableMobles = new VulTable(callbacks);
        //JTable table = new JTable(tableMobles);
        Vtable = new Vultableextend(tableMobles,Udatas,callbacks,OriginalRequestTextEditor,HRequestTextEditor,NoAuthHRequestTextEditor,OriginalResponseTextEditor,HResponseTextEditor,NoAuthHResponseTextEditor,newHeaderField,lowHeaderField);


        JScrollPane tableScrollPane = new JScrollPane(Vtable);


        // 创建请求响应区域
        //JPanel splitPane = createRequestResponseSplitPane();

        // 组合表格和请求响应区域
        mjSplitPane.add(tableScrollPane,"left");
        mjSplitPane.add(splitPane, "right");


        panel.add(mjSplitPane,BorderLayout.CENTER);

        return panel;
    }

    private JSplitPane createResultPanel() {
        JPanel Lpanel = new JPanel(new BorderLayout());
        JPanel Rpanel = new JPanel(new BorderLayout());
        JTabbedPane Ltable = new JTabbedPane();
        // 新增 OriginalRequestTextEditor 用于展示原始请求
        //OriginalRequestTextEditor = callbacks.createMessageEditor(this, false);
        OriginalRequestTextEditor = callbacks.createMessageEditor(BurpLikeUI.this, false);
        Ltable.addTab("Original Request", OriginalRequestTextEditor.getComponent());


        // 创建用于展示修改后的请求的组件
        HRequestTextEditor = callbacks.createMessageEditor(null, false);
        Ltable.addTab("Modified Request", HRequestTextEditor.getComponent());


        // 创建用于展示去掉鉴权字段后请求的组件
        NoAuthHRequestTextEditor = callbacks.createMessageEditor(null, false);
        Ltable.addTab("NoAuth Request", NoAuthHRequestTextEditor.getComponent());





        JTabbedPane Rtable = new JTabbedPane();

        // 新增 OriginalResponseTextEditor 用于展示原始响应
        OriginalResponseTextEditor = callbacks.createMessageEditor(null, false);
        Rtable.addTab("Original Response", OriginalResponseTextEditor.getComponent());

        HResponseTextEditor = callbacks.createMessageEditor(null, false);
        Rtable.addTab("Modified Response", HResponseTextEditor.getComponent());

        NoAuthHResponseTextEditor = callbacks.createMessageEditor(null, false);
        Rtable.addTab("NoAuth Response", NoAuthHResponseTextEditor.getComponent());

        Ltable.addChangeListener(e -> {
            int selectedIndex = Ltable.getSelectedIndex();
            Rtable.setSelectedIndex(selectedIndex);
        });

        Lpanel.add(Ltable);
        Rpanel.add(Rtable);
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, Lpanel, Rpanel);
        splitPane.setResizeWeight(0.5); // 平均分配空间

        return splitPane;

    }



    private JPanel createRequestResponseSplitPane() {
        // 简化测试：直接创建一个简单的 JSplitPane
        //JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        JSplitPane splitPane = createResultPanel();

        // 左侧面板
        /**
        JTabbedPane leftPanel = new JTabbedPane();
        OriginalRequestTextEditor = callbacks.createMessageEditor(null, false);
        leftPanel.addTab("Original Request", OriginalRequestTextEditor.getComponent());
        HRequestTextEditor = callbacks.createMessageEditor(null, false);
        leftPanel.addTab("Modified Request", HRequestTextEditor.getComponent());
        NoAuthHRequestTextEditor = callbacks.createMessageEditor(null, false);
        leftPanel.addTab("NoAuth Request", NoAuthHRequestTextEditor.getComponent());
        // 右侧面板
        JPanel rightPanel = new JPanel();
        rightPanel.add(new JLabel("Right Panel Content"));
        //rightPanel.add(new JLabel("Right Panel Content 01"));

        // 设置 JSplitPane 的两个面板
        splitPane.setLeftComponent(leftPanel);
        splitPane.setRightComponent(rightPanel);
        splitPane.setResizeWeight(0.5);
         **/

        // 创建按钮面板
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 5));
        JButton addButton = new JButton("Run");
        addButton.addActionListener(e -> Vtable.replaySelectedUrls());
        JButton editButton = new JButton("Clear Requests");
        JButton removeButton = new JButton("Clear Responses");

        buttonPanel.add(addButton);
        buttonPanel.add(editButton);
        buttonPanel.add(removeButton);

        // 创建主面板
        JPanel MainPanel = new JPanel(new BorderLayout());
        MainPanel.add(splitPane, BorderLayout.CENTER);
        MainPanel.add(buttonPanel, BorderLayout.SOUTH);

        return MainPanel;
    }




    private JPanel createConfigPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10)); // 添加面板边距

        // 新增：路径输入框和按钮面板
        JPanel pathPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel pathLabel = new JLabel("Rules Path:");
        JTextField pathField = new JTextField(30); // 设置初始宽度
        JButton onlineUpdateButton = new JButton("Online Update");
        JButton reloadButton = new JButton("Reload");

        pathPanel.add(pathLabel);
        pathPanel.add(pathField);
        pathPanel.add(onlineUpdateButton);
        pathPanel.add(reloadButton);

        // 路径输入框默认值
        pathField.setText("E:\\burp2021\\burp2021\\config_data.json");

        // 按钮点击事件处理
        onlineUpdateButton.addActionListener(e -> {
            // 在线更新逻辑
            String newPath = pathField.getText();
            // TODO: 实现在线更新功能
            JOptionPane.showMessageDialog(null, "Online update from: " + newPath);
        });

        reloadButton.addActionListener(e -> {
            // 重新加载逻辑
            String newPath = pathField.getText();
            // TODO: 实现重新加载功能
            JOptionPane.showMessageDialog(null, "Reload from: " + newPath);
        });

        Border border = BorderFactory.createLineBorder(Color.BLACK, 1);


        JPanel pathandurlpanel = new JPanel(new BorderLayout());
        pathandurlpanel.add(pathPanel, BorderLayout.NORTH);
        JPanel urlpeizhiPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel urlpeizhiLabel = new JLabel("url配置: ");
        //JTextArea urlpeizhiField = new JTextArea();
        urlpeizhiField.setBorder(border);
        urlpeizhiPanel.add(urlpeizhiLabel);
        urlpeizhiPanel.add(urlpeizhiField);
        pathandurlpanel.add(urlpeizhiPanel, BorderLayout.CENTER);




        JPanel panel_center = new JPanel(new BorderLayout());

        //panel.add(pathPanel, BorderLayout.NORTH);
        panel_center.add(pathandurlpanel, BorderLayout.NORTH);


        // 新增：添加两个如图所示的UI元素
        JPanel newHeaderPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        JLabel newHeaderLabel = new JLabel("水平header: ");
        //newHeaderField = new JTextArea(3, 150); // 设置初始宽度

        // 创建边框并设置给 lowHeaderField
        //Border border = BorderFactory.createLineBorder(Color.BLACK, 1);
        newHeaderField.setBorder(border);

        //JScrollPane newHeaderScrollPane = new JScrollPane(newHeaderField);


        newHeaderPanel.add(newHeaderLabel);
        newHeaderPanel.add(newHeaderField);


        // 新增：添加两个如图所示的UI元素
        JPanel lowHeaderPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel lowHeaderLabel = new JLabel("垂直header: ");
        lowHeaderField = new JTextArea(3, 150); // 设置初始行数和列数

        // 创建边框并设置给 lowHeaderField
        //Border border = BorderFactory.createLineBorder(Color.BLACK, 1);
        lowHeaderField.setBorder(border);

        lowHeaderPanel.add(lowHeaderLabel);
        lowHeaderPanel.add(lowHeaderField);


        //JPanel urlpeizhiPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        //JLabel urlpeizhiLabel = new JLabel("url配置: ");
        //JTextArea urlpeizhiField = new JTextArea();
        //urlpeizhiField.setBorder(border);
        //urlpeizhiPanel.add(urlpeizhiLabel);
        //urlpeizhiPanel.add(urlpeizhiField);






        //panel.add(newHeaderPanel, BorderLayout.CENTER);
        //panel_center.add(urlpeizhiPanel, BorderLayout.NORTH);
        panel_center.add(newHeaderPanel, BorderLayout.SOUTH);
        panel_center.add(lowHeaderPanel, BorderLayout.CENTER);
        panel.add(panel_center, BorderLayout.NORTH);




        JScrollPane tableScrollPane = new JScrollPane(configtable);
        panel.add(tableScrollPane, BorderLayout.CENTER);

        //panel_center.add(tableScrollPane,BorderLayout.NORTH);

        // 创建按钮面板
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 5)); // 水平布局，左对齐，组件间间距为10
        JButton addButton = new JButton("Add");
        JButton editButton = new JButton("Edit");
        JButton removeButton = new JButton("Remove");
        JButton saveButton = new JButton("Save"); // 新增 Save 按钮

        // 为按钮添加监听器
        //addButton.addActionListener(e -> addRow(tableModel));
        //editButton.addActionListener(e -> editRow(tableModel, table));
        //removeButton.addActionListener(e -> removeRow(tableModel, table));
        //saveButton.addActionListener(e -> saveConfigData()); // 新增 Save 按钮的监听器
        configbuttonlisten configbuttonlisten = new configbuttonlisten();


        addButton.addActionListener(e -> configbuttonlisten.addRow(configtableModel));
        editButton.addActionListener(e -> configbuttonlisten.editRow(configtableModel, configtable));
        removeButton.addActionListener(e -> configbuttonlisten.removeRow(configtableModel, configtable));
        saveButton.addActionListener(e -> saveConfigData()); // 新增 Save 按钮的监听器


        buttonPanel.add(addButton);
        buttonPanel.add(editButton);
        buttonPanel.add(removeButton);
        buttonPanel.add(saveButton); // 将 Save 按钮添加到按钮面板


        //JPanel buttonPanel_center = new JPanel(new FlowLayout());
        //buttonPanel_center.add(buttonPanel, FlowLayout.CENTER);



        // 添加按钮面板到底部
        panel.add(buttonPanel, BorderLayout.SOUTH);
        //panel_center.add(buttonPanel,BorderLayout.SOUTH);
        //panel.add(panel_center, BorderLayout.SOUTH);

        return panel;
    }


    /**
     * 获取 newHeaderField 和 lowHeaderField 的内容
     *
     * @return 一个包含两个元素的字符串数组，第一个是 newHeaderField 的内容，第二个是 lowHeaderField 的内容
     */
    public String[] getHeaderValues() {
        /**
        // 获取 pathField 所在的面板
        Component configComponent = tabbedPane.getComponentAt(1); // 获取 Config 标签页
        if (configComponent instanceof JPanel) {
            JPanel configPanel = (JPanel) configComponent;
            for (Component child : configPanel.getComponents()) {
                if (child instanceof JPanel) {
                    JPanel subPanel = (JPanel) child;
                    for (Component subChild : subPanel.getComponents()) {
                        if (subChild instanceof JTextArea) {
                            // 寻找 newHeaderField 和 lowHeaderField
                            JTextArea textArea = (JTextArea) subChild;
                            if (textArea.getName() == null || !textArea.getName().equals("lowHeaderField")) {
                                continue; // 跳过不是 lowHeaderField 的组件
                            }
                        }
                    }
                }
            }
        }
         **/

        // 假设这两个字段已经在 createConfigPanel 方法中初始化
        String newHeaderValue = newHeaderField.getText();
        String lowHeaderValue = lowHeaderField.getText();

        return new String[]{newHeaderValue, lowHeaderValue};
    }


    // 添加新行的方法
    // 添加新行的方法
    private void addRow(ConfigTableModel tableModel) {
        JCheckBox loadedField = new JCheckBox(); // Loaded 字段使用复选框
        JTextField nameField = new JTextField();
        JTextField fRegexField = new JTextField();
        JTextField sRegexField = new JTextField();
        JTextField formatField = new JTextField();
        JTextField colorField = new JTextField();
        JTextField scopeField = new JTextField();
        JTextField engineField = new JTextField();
        JCheckBox sensitiveField = new JCheckBox(); // Sensitive 字段使用复选框

        JPanel inputPanel = new JPanel(new GridLayout(0, 2)); // 0 表示行数不定，2 表示两列
        inputPanel.add(new JLabel("Loaded:"));
        inputPanel.add(loadedField);
        inputPanel.add(new JLabel("Name:"));
        inputPanel.add(nameField);
        inputPanel.add(new JLabel("F-Regex:"));
        inputPanel.add(fRegexField);
        inputPanel.add(new JLabel("S-Regex:"));
        inputPanel.add(sRegexField);
        inputPanel.add(new JLabel("Format:"));
        inputPanel.add(formatField);
        inputPanel.add(new JLabel("Color:"));
        inputPanel.add(colorField);
        inputPanel.add(new JLabel("Scope:"));
        inputPanel.add(scopeField);
        inputPanel.add(new JLabel("Engine:"));
        inputPanel.add(engineField);
        inputPanel.add(new JLabel("Sensitive:"));
        inputPanel.add(sensitiveField);

        //String[] test = getHeaderValues();
        //.println(test[0]);

        int result = JOptionPane.showConfirmDialog(null, inputPanel, "Add New Row", JOptionPane.OK_CANCEL_OPTION);
        if (result == JOptionPane.OK_OPTION) {
            ConfigTableItem newItem = new ConfigTableItem(
                    Boolean.parseBoolean(loadedField.getText()),
                    nameField.getText(),
                    fRegexField.getText(),
                    sRegexField.getText(),
                    formatField.getText(),
                    colorField.getText(),
                    scopeField.getText(),
                    engineField.getText(),
                    sensitiveField.isSelected()
            );
            tableModel.addRow(newItem);
        }
    }
    // 编辑选中行的方法
    private void editRow(ConfigTableModel tableModel, JTable table) {
        int selectedRow = table.getSelectedRow();
        if (selectedRow != -1) {
            // 使用 ConfigTableModel 的 getItems() 方法获取完整的 ConfigTableItem 对象
            ConfigTableItem selectedItem = tableModel.getItems().get(selectedRow);

            // 创建 JTextField 和 JCheckBox 并设置初始值
            JCheckBox loadedField = new JCheckBox();
            loadedField.setSelected(selectedItem.isLoaded());
            JTextField nameField = new JTextField(selectedItem.getName());
            JTextField fRegexField = new JTextField(selectedItem.getfRegex());
            JTextField sRegexField = new JTextField(selectedItem.getsRegex());
            JTextField formatField = new JTextField(selectedItem.getFormat());
            JTextField colorField = new JTextField(selectedItem.getColor());
            JTextField scopeField = new JTextField(selectedItem.getScope());
            JTextField engineField = new JTextField(selectedItem.getEngine());
            JCheckBox sensitiveField = new JCheckBox();
            sensitiveField.setSelected(selectedItem.isSensitive());

            // 创建 JPanel 并设置布局
            JPanel inputPanel = new JPanel(new GridLayout(0, 2)); // 0 表示行数不定，2 表示两列
            inputPanel.add(new JLabel("Loaded:"));
            inputPanel.add(loadedField);
            inputPanel.add(new JLabel("Name:"));
            inputPanel.add(nameField);
            inputPanel.add(new JLabel("F-Regex:"));
            inputPanel.add(fRegexField);
            inputPanel.add(new JLabel("S-Regex:"));
            inputPanel.add(sRegexField);
            inputPanel.add(new JLabel("Format:"));
            inputPanel.add(formatField);
            inputPanel.add(new JLabel("Color:"));
            inputPanel.add(colorField);
            inputPanel.add(new JLabel("Scope:"));
            inputPanel.add(scopeField);
            inputPanel.add(new JLabel("Engine:"));
            inputPanel.add(engineField);
            inputPanel.add(new JLabel("Sensitive:"));
            inputPanel.add(sensitiveField);

            // 显示弹窗并获取用户选择
            int result = JOptionPane.showConfirmDialog(null, inputPanel, "Edit Row", JOptionPane.OK_CANCEL_OPTION);
            if (result == JOptionPane.OK_OPTION) {
                ConfigTableItem updatedItem = new ConfigTableItem(
                        loadedField.isSelected(),
                        nameField.getText(),
                        fRegexField.getText(),
                        sRegexField.getText(),
                        formatField.getText(),
                        colorField.getText(),
                        scopeField.getText(),
                        engineField.getText(),
                        sensitiveField.isSelected()
                );
                tableModel.updateRow(selectedRow, updatedItem);
            }
        } else {
            JOptionPane.showMessageDialog(null, "Please select a row to edit.");
        }
    }

    // 删除选中行的方法
    private void removeRow(ConfigTableModel tableModel, JTable table) {
        int selectedRow = table.getSelectedRow();
        if (selectedRow != -1) {
            tableModel.removeRow(selectedRow);
        } else {
            JOptionPane.showMessageDialog(null, "Please select a row to delete.");
        }
    }

    public void setCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

  /**

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            BurpLikeUI frame = new BurpLikeUI();
            frame.setVisible(true);
        });
    }
**/
    @Override
    public String getTabCaption() {
        return "MyYQT";
    }

    @Override
    public Component getUiComponent() {
        return tabbedPane;
    }

    @Override
    public IHttpService getHttpService() {
        return this.currentlyDisplayedItem.getHttpService();
    }

    @Override
    public byte[] getRequest() {
        return this.currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return currentlyDisplayedItem.getResponse();
    }


    // 新增 ConfigItem 类
    static class ConfigTableItem {
        boolean loaded;
        String name;
        String fRegex;
        String sRegex;
        String format;
        String color;
        String scope;
        String engine;
        boolean sensitive;

        public ConfigTableItem(boolean loaded, String name, String fRegex, String sRegex, String format, String color, String scope, String engine, boolean sensitive) {
            this.loaded = loaded;
            this.name = name;
            this.fRegex = fRegex;
            this.sRegex = sRegex;
            this.format = format;
            this.color = color;
            this.scope = scope;
            this.engine = engine;
            this.sensitive = sensitive;
        }

        // Getters and Setters
        public boolean isLoaded() { return loaded; }
        public void setLoaded(boolean loaded) { this.loaded = loaded; }
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public String getfRegex() { return fRegex; }
        public void setfRegex(String fRegex) { this.fRegex = fRegex; }
        public String getsRegex() { return sRegex; }
        public void setsRegex(String sRegex) { this.sRegex = sRegex; }
        public String getFormat() { return format; }
        public void setFormat(String format) { this.format = format; }
        public String getColor() { return color; }
        public void setColor(String color) { this.color = color; }
        public String getScope() { return scope; }
        public void setScope(String scope) { this.scope = scope; }
        public String getEngine() { return engine; }
        public void setEngine(String engine) { this.engine = engine; }
        public boolean isSensitive() { return sensitive; }
        public void setSensitive(boolean sensitive) { this.sensitive = sensitive; }
    }


    // 新增 ConfigTableModel 类
    static class ConfigTableModel extends AbstractTableModel {
        private List<ConfigTableItem> items;

        public ConfigTableModel(List<ConfigTableItem> items) {
            this.items = items;
        }

        @Override
        public int getRowCount() {
            return items.size();
        }

        @Override
        public int getColumnCount() {
            return 9; // 根据 ConfigTableItem 的属性数量调整
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            ConfigTableItem item = items.get(rowIndex);
            switch (columnIndex) {
                case 0: return item.isLoaded();
                case 1: return item.getName();
                case 2: return item.getfRegex();
                case 3: return item.getsRegex();
                case 4: return item.getFormat();
                case 5: return item.getColor();
                case 6: return item.getScope();
                case 7: return item.getEngine();
                case 8: return item.isSensitive();
                default: return null;
            }
        }

        @Override
        public String getColumnName(int column) {
            switch (column) {
                case 0: return "Loaded";
                case 1: return "Name";
                case 2: return "F-Regex";
                case 3: return "S-Regex";
                case 4: return "Format";
                case 5: return "Color";
                case 6: return "Scope";
                case 7: return "Engine";
                case 8: return "Sensitive";
                default: return "";
            }
        }

        @Override
        public boolean isCellEditable(int rowIndex, int columnIndex) {
            return false; // 根据需求调整是否可编辑
        }

        public void addRow(ConfigTableItem item) {
            items.add(item);
            fireTableRowsInserted(items.size() - 1, items.size() - 1);
        }

        public void removeRow(int rowIndex) {
            if (rowIndex >= 0 && rowIndex < items.size()) {
                items.remove(rowIndex);
                fireTableRowsDeleted(rowIndex, rowIndex);
            }
        }

        public void updateRow(int rowIndex, ConfigTableItem item) {
            if (rowIndex >= 0 && rowIndex < items.size()) {
                items.set(rowIndex, item);
                fireTableRowsUpdated(rowIndex, rowIndex);
            }
        }

        // 新增方法：获取底层数据列表
        public List<ConfigTableItem> getItems() {
            return items;
        }

        // 新增方法：设置底层数据列表
        public void setItems(List<ConfigTableItem> items) {
            this.items = items;
            fireTableDataChanged();
        }
    }



}
