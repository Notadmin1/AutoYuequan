package burp;

import javax.swing.*;
import java.util.List;

public class MyScancheck implements IScannerCheck{

    //private final List<VulTableModel> Udatas;
    private final VulTable vulTable;
    private final ParameterModelTabel parameterModelTabel;
    private final JTextArea urlpeizhiField;
    private IBurpExtenderCallbacks callbacks;
    private JTable configtable;
    public MyScancheck(IBurpExtenderCallbacks callbacks,JTable configtable, VulTable vulTable, ParameterModelTabel parameterModelTabel, JTextArea urlpeizhiField)
    {
        this.callbacks = callbacks;
        this.configtable = configtable;
        this.vulTable = vulTable;
        this.parameterModelTabel = parameterModelTabel;
        this.urlpeizhiField = urlpeizhiField;
        callbacks.printOutput("[关键] 自定义扫描器注册成功");
    }


    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        callbacks.printOutput("**************************************11");
        AutoRequest autoRequest = new AutoRequest(callbacks, baseRequestResponse, configtable,vulTable,parameterModelTabel,urlpeizhiField);
        autoRequest.processRequestResponse();
        return null;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }
}
