package burp;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.io.PrintWriter;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class VulTable extends AbstractTableModel {


    List<VulTableModel> Udatas;
    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;
    private PrintWriter stdout;



    public VulTable(IBurpExtenderCallbacks callbacks,List<VulTableModel> Udatas) {
        this.helpers = callbacks.getHelpers();
        this.callbacks = callbacks;
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.Udatas = Udatas;
    }


    @Override
    public int getRowCount() {
        return this.Udatas.size();
    }

    @Override
    public int getColumnCount() {
        return 10;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        VulTableModel datas = this.Udatas.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return Integer.valueOf(datas.Id);
            case 1:
                return datas.Method;
            case 2:
                return datas.URL;
            case 3:
                return datas.Status;
            case 4:
                return datas.issue;
            case 5:
                return datas.ShuipingSentivite;
            case 6:
                return datas.NoAuthSentivite;
            case 7:
                return datas.ShuipingSimilarity;
            case 8:
                return datas.NoAuthSimilarity;
            case 9:
                return datas.Replay;
        }
        return null;
    }

    public String getColumnName(int columnIndex) {
        switch (columnIndex) {
            case 0:
                return "#";
            case 1:
                return "Method";
            case 2:
                return "URL";
            case 3:
                return "Status";
            case 4:
                return "Issue";
            case 5:
                return "ShuipingSentivite";
            case 6:
                return "NoAuthSentivite";
            case 7:
                return "ShuipingSimilarity";
            case 8:
                return "NoAuthSimilarity";
            case 9:
                return "Replay";
        }
        return null;
    }


    public void addUrlFromProxy(IHttpRequestResponse messageInfo,String issue) {
        IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
        URL url = requestInfo.getUrl();
        String method = requestInfo.getMethod();
        IResponseInfo responseInfo = helpers.analyzeResponse(messageInfo.getResponse());
        int statusCode = responseInfo.getStatusCode();
        //String issue = "From Proxy";

        // 创建新的IHttpRequestResponse对象，避免共享引用
        IHttpRequestResponse newMessageInfo = callbacks.saveBuffersToTempFiles(messageInfo);

        callbacks.printOutput("CustomContextMenu actionPerformed55555:"+newMessageInfo.toString());


        synchronized (this.Udatas) {
            int row = this.Udatas.size();
            // 使用新的messageInfo对象创建TablesData
            this.Udatas.add(new VulTableModel(row, method, url.toString(), String.valueOf(statusCode), issue, newMessageInfo));
            fireTableRowsInserted(row, row);
        }

    }





}
