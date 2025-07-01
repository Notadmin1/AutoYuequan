package burp;

import javafx.fxml.FXMLLoader;

import javax.swing.*;
import javax.swing.table.TableModel;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

public class Vultableextend extends JTable {
    private final List<VulTableModel> Udatas;;
    private final IExtensionHelpers helpers;
    private final PrintWriter stdout;
    private IBurpExtenderCallbacks callbacks;

    private IMessageEditor OriginalRequestTextEditor;
    private IMessageEditor HRequestTextEditor;
    private IMessageEditor NoAuthHRequestTextEditor;
    private IMessageEditor OriginalResponseTextEditor;
    private IMessageEditor HResponseTextEditor;
    private IMessageEditor NoAuthHResponseTextEditor;
    //private VulTable tableModel;
    private java.util.Properties headerConfig = new Properties();;
    //private Properties headerConfig = new Properties();

    private JTextArea newHeaderField;
    private JTextArea lowHeaderField;



    public Vultableextend(VulTable tableModel,List<VulTableModel> Udatas,IBurpExtenderCallbacks callbacks,IMessageEditor OriginalRequestTextEditor,IMessageEditor HRequestTextEditor, IMessageEditor NoAuthHRequestTextEditor, IMessageEditor OriginalResponseTextEditor, IMessageEditor HResponseTextEditor, IMessageEditor NoAuthHResponseTextEditor, JTextArea newHeaderField,JTextArea lowHeaderField) {
        super(tableModel);
        this.Udatas = Udatas;
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.callbacks = callbacks;
        this.stdout = new PrintWriter(callbacks.getStdout(), true);

        this.OriginalRequestTextEditor = OriginalRequestTextEditor;
        this.HRequestTextEditor = HRequestTextEditor;
        this.NoAuthHRequestTextEditor = NoAuthHRequestTextEditor;
        this.OriginalResponseTextEditor = OriginalResponseTextEditor;
        this.HResponseTextEditor = HResponseTextEditor;
        this.NoAuthHResponseTextEditor = NoAuthHResponseTextEditor;
        //loadHeaderConfig();

        this.newHeaderField = newHeaderField;
        this.lowHeaderField = lowHeaderField;

    }



    public void changeSelection(int row, int col, boolean toggle, boolean extend) {
        try {
            // 确保行号在有效范围内
            if (row < 0 || row >= this.Udatas.size()) {
                stdout.println("Invalid row selection: " + row);
                return;
            }

            // 确保 Udatas 列表不为空
            if (this.Udatas.isEmpty()) {
                stdout.println("Udatas list is empty.");
                return;
            }

            stdout.println("Selected row: " + row);

            // 获取选中的行数据
            int modelRow = convertRowIndexToModel(row); // 添加这行来明确 modelRow 的值
            stdout.println("Model row: " + modelRow); // 打印 modelRow 的值

            if (modelRow < 0 || modelRow >= this.Udatas.size()) { // 检查 modelRow 是否有效
                stdout.println("Invalid model row: " + modelRow);
                return;
            }

            VulTableModel dataEntry = this.Udatas.get(modelRow);

            if (dataEntry == null) { // 检查 dataEntry 是否为 null
                stdout.println("DataEntry is null.");
                return;
            }

            // 输出 dataEntry 的内容
            stdout.println("Data Entry Content:");
            stdout.println("ID: " + dataEntry.Id);
            stdout.println("Method: " + dataEntry.Method);
            stdout.println("URL: " + dataEntry.URL);
            stdout.println("Status: " + dataEntry.Status);
            stdout.println("Issue: " + dataEntry.issue);
            stdout.println("ShuipingSentivite: " + dataEntry.ShuipingSentivite);
            stdout.println("NoAuthSentivite: " + dataEntry.NoAuthSentivite);
            stdout.println("ShuipingSimilarity: " + dataEntry.ShuipingSimilarity);
            stdout.println("NoAuthSimilarity: " + dataEntry.NoAuthSimilarity);

            // 输出 requestResponse 信息
            if (dataEntry.requestResponse != null) {
                stdout.println("RequestResponse Info:");
                stdout.println("Request: " + new String(dataEntry.requestResponse.getRequest(), StandardCharsets.UTF_8));
                stdout.println("Response: " + new String(dataEntry.requestResponse.getResponse(), StandardCharsets.UTF_8));
            } else {
                stdout.println("RequestResponse is null.");
            }

            // 输出 ModifiedRequestResponse 信息
            if (dataEntry.ModifiedRequestResponse != null) {
                stdout.println("ModifiedRequestResponse Info:");
                stdout.println("Request: " + new String(dataEntry.ModifiedRequestResponse.getRequest(), StandardCharsets.UTF_8));
                stdout.println("Response: " + new String(dataEntry.ModifiedRequestResponse.getResponse(), StandardCharsets.UTF_8));
            } else {
                stdout.println("ModifiedRequestResponse is null.");
            }


            // 更新原始请求和响应编辑器
            try {
                if (dataEntry == null) {
                    stdout.println("Warning: dataEntry is null");
                    OriginalRequestTextEditor.setMessage(new byte[0], true);
                    OriginalResponseTextEditor.setMessage(new byte[0], false);
                    return;
                }
                
                if (dataEntry.requestResponse == null) {
                    stdout.println("Warning: requestResponse is null");
                    OriginalRequestTextEditor.setMessage(new byte[0], true);
                    OriginalResponseTextEditor.setMessage(new byte[0], false);
                    return;
                }
                
                byte[] request = dataEntry.requestResponse.getRequest();
                byte[] response = dataEntry.requestResponse.getResponse();
                
                if (request == null) {
                    stdout.println("Warning: request is null");
                    request = new byte[0];
                }
                
                if (response == null) {
                    stdout.println("Warning: response is null");
                    response = new byte[0];
                }
                
                OriginalRequestTextEditor.setMessage(request, true);
                OriginalResponseTextEditor.setMessage(response, false);
            } catch (Exception e) {
                stdout.println("Error updating message editors: " + e.toString());
                e.printStackTrace(new PrintWriter(callbacks.getStderr()));
                OriginalRequestTextEditor.setMessage(new byte[0], true);
                OriginalResponseTextEditor.setMessage(new byte[0], false);
            }



            // 更新修改后的请求和响应编辑器
            if (dataEntry.ModifiedRequestResponse != null) {
                HRequestTextEditor.setMessage(dataEntry.ModifiedRequestResponse.getRequest(), true);
                HResponseTextEditor.setMessage(dataEntry.ModifiedRequestResponse.getResponse(), false);
            } else {
                // 如果 ModifiedRequestResponse 为 null，清空 HRequestTextEditor
                HRequestTextEditor.setMessage(new byte[0], true);
                HResponseTextEditor.setMessage(new byte[0], false);
            }

            // 更新无鉴权请求和响应编辑器
            if (dataEntry.NoAuthRequestResponse != null) {
                NoAuthHRequestTextEditor.setMessage(dataEntry.NoAuthRequestResponse.getRequest(), true);
                NoAuthHResponseTextEditor.setMessage(dataEntry.NoAuthRequestResponse.getResponse(), false);
            } else {
                // 如果 ModifiedRequestResponse 为 null，清空 HRequestTextEditor
                NoAuthHRequestTextEditor.setMessage(new byte[0], true);
                NoAuthHResponseTextEditor.setMessage(new byte[0], false);
            }


            // 调用父类的 changeSelection 方法完成选中操作
            super.changeSelection(row, col, toggle, extend);

            // 强制刷新 UI
            //this.repaint();
            //this.revalidate();
        } catch (Exception e) {
            stdout.println("Error in changeSelection: " + e.getMessage());
            e.printStackTrace(new PrintWriter(callbacks.getStderr()));
        }
    }


    // 新增方法：加载header配置
    private void loadHeaderConfig() {
        String configPath = "E:\\工作总结\\测试提效工具\\burpExtend\\config\\header_config.properties";
        try (InputStream input = new FileInputStream(configPath)) {
            if (input == null) {
                stdout.println("Could not find header_config.properties at " + configPath);
                return;
            }
            //FXMLLoader headerConfig;
            headerConfig.load(input);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }






    public void replaySelectedUrls() {
        //VulTableModel datas = null;
        loadHeaderConfig();
        int[] selectedRows = this.getSelectedRows();
        if (selectedRows.length == 0) {
            stdout.println("No URLs selected.");
            return;
        }

        for (int row : selectedRows) {
            VulTableModel dataEntry = Udatas.get(row);
            stdout.println("**********************************************************");
            //new ReplayRequestWorker(row,dataEntry.requestResponse,OriginalRequestTextEditor, OriginalResponseTextEditor,HRequestTextEditor,HResponseTextEditor,NoAuthHRequestTextEditor,NoAuthHResponseTextEditor).execute();
            //Properties headerConfig;
            new MRquest(callbacks, headerConfig, this, dataEntry.requestResponse,row,Udatas, newHeaderField,lowHeaderField).execute();
        }
    }


}
