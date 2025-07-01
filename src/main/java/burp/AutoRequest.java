package burp;

import javax.swing.*;
import java.io.PrintWriter;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.ArrayList;
import java.util.List;

public class AutoRequest {
    private final IExtensionHelpers helper;
    private final PrintWriter stdout;
    private final PrintWriter stderr;
    //private final List<VulTableModel> Udatas;
    private final VulTable vulTable;
    private final ParameterModelTabel parameterModelTabel;
    private final JTextArea urlpeizhiField;
    private IBurpExtenderCallbacks callbacks;
    private IHttpRequestResponse requestResponse;
    private JTable configtable;

    List<String> filteredDomains = new ArrayList<>(); // 新增域名过滤配置变量



    public AutoRequest(IBurpExtenderCallbacks callbacks, IHttpRequestResponse requestResponse, JTable configtable, VulTable vulTable,ParameterModelTabel parameterModelTabel,JTextArea urlpeizhiField ) {
        this.requestResponse = requestResponse;
        this.configtable = configtable;
        this.callbacks = callbacks;
        this.helper = callbacks.getHelpers();

        this.stdout = new PrintWriter(callbacks.getStdout(),true);
        this.stderr = new PrintWriter(callbacks.getStderr(),true);

        this.vulTable = vulTable;


        this.parameterModelTabel = parameterModelTabel;

        this.urlpeizhiField = urlpeizhiField;

        //processRequestResponse();
    }


    // 在 AutoRequest 类中添加以下方法
    public void updateFilteredDomainsFromField() {
        // 清空现有域名列表
        filteredDomains.clear();

        // 从文本域获取配置内容
        String configText = urlpeizhiField.getText();
        if (configText == null || configText.isEmpty()) {
            return;
        }

        // 按行分割并添加到域名列表
        String[] lines = configText.split("\\r?\\n");
        for (String line : lines) {
            String domain = line.trim();
            if (!domain.isEmpty() && !filteredDomains.contains(domain)) {
                filteredDomains.add(domain);
            }
        }

        // 打印更新日志（可选）
        stdout.println("更新域名过滤配置: " + filteredDomains);
    }






    private void sendParamter(IParameter param,String domain){
        boolean exists = false;
        // 检查参数是否已在表中
        for (int i = 0; i < parameterModelTabel.getRowCount(); i++) {
            String existingParam = (String) parameterModelTabel.getValueAt(i, 1);
            if (param.getName().equals(existingParam)) {
                exists = true;
                break;
            }
        }
        // 如果参数不存在则添加到表中
        if (!exists) {
            //int row = parameterModelTabel.Udatas.size();
            //byte typeBytes = param.getType();
            if (param.getValue() != null && param.getValue().length()>0){
                stdout.println("*****************************************666666");
                parameterModelTabel.addRow(param,domain);
            }

        }
    }


    // 获取参数名的封装函数，只获取body、url、xml中的参数
    private List<IParameter> getParameter() {
        List<IParameter> paramNames = new ArrayList<>();
        List<String> ruleexclude = new ArrayList<>();

        // 获取配置模型
        ConfigTableModelV2 tableModel = (ConfigTableModelV2) configtable.getModel();
        //List<ConfigTableItemV2> rules = tableModel.getItems();
        for (ConfigTableItemV2 item : tableModel.getItems()) {
            if (item.isLoaded()) {
                // 只处理参数相关的匹配规则
                if ("过滤参数名".equals(item.getposition())) {
                    ruleexclude.add(item.getcontent());
                }
            }}



        // 获取请求数据并分析请求体中的参数
        byte[] requestBodyBytes = requestResponse.getRequest(); // 获取请求体内容
        IRequestInfo requestInfo = helper.analyzeRequest(requestBodyBytes);

        for (IParameter param : requestInfo.getParameters()) {
            // 只获取常见的POST body参数类型
            if (param.getType() == IParameter.PARAM_BODY ||
                param.getType() == IParameter.PARAM_JSON ||
                param.getType() == IParameter.PARAM_MULTIPART_ATTR ||
                param.getType() == IParameter.PARAM_URL ||
            param.getType() == IParameter.PARAM_XML) {
                if (ruleexclude.contains(param.getName())) {
                    continue;
                } else {
                    paramNames.add(param);
                }
            }
        }
        return paramNames;
    }

    private List<String> getParameterNames() {
        List<String> paramNamesList = new ArrayList<>();
        List<IParameter> parameters = getParameter();
        for (IParameter param : parameters) {
            paramNamesList.add(param.getName());
        }
        return paramNamesList;
    }

    /**
     * 匹配参数并返回匹配结果
     * @return 返回匹配成功的参数键值对列表
     */
    private List<MatchResult> matchParameters() {
        List<MatchResult> results = new ArrayList<>();

        // 获取配置模型
        ConfigTableModelV2 tableModel = (ConfigTableModelV2) configtable.getModel();

        // 遍历所有启用的规则
        for (ConfigTableItemV2 item : tableModel.getItems()) {
            if (item.isLoaded()) {
                // 只处理参数相关的匹配规则
                if ("参数名".equals(item.getposition()) || "参数值".equals(item.getposition())) {
                    List<IParameter> parameters = getParameter();

                    // 遍历每个参数进行匹配
                    for (IParameter param : parameters) {
                        String paramValue = param.getValue();

                        // 根据匹配位置获取匹配内容
                        String contentToMatch = "";
                        if ("参数名".equals(item.getposition())) {
                            contentToMatch = param.getName();
                        } else if ("参数值".equals(item.getposition())) {
                            contentToMatch = param.getValue();
                        }

                        // 根据匹配方式进行匹配
                        boolean matchResult = false;
                        switch (item.getmethod()) {
                            case "正则表达式":
                                try {
                                    Pattern pattern = Pattern.compile(item.getcontent());
                                    Matcher matcher = pattern.matcher(contentToMatch);
                                    matchResult = matcher.find();
                                } catch (Exception e) {
                                    System.err.println("Invalid regex pattern: " + item.getcontent());
                                }
                                break;
                            case "字符匹配":
                                matchResult = contentToMatch.contains(item.getcontent());
                                break;
                        }

                        // 如果匹配成功，添加到结果列表
                        if (matchResult) {
                            results.add(new MatchResult(
                                item.getName(),
                                param.getName(),
                                param.getValue(),
                                item.getmethod(),
                                item.getcontent()
                            ));
                        }
                    }
                }
            }
        }

        return results;
    }

    /**
     * 匹配非参数类内容（返回body、cookies等）
     * @return 返回匹配成功的非参数类内容结果列表
     */
    private List<String> matchNonParameterContent() {
        List<String> results = new ArrayList<>();

        // 获取配置模型
        ConfigTableModelV2 tableModel = (ConfigTableModelV2) configtable.getModel();

        // 遍历所有启用的规则
        for (ConfigTableItemV2 item : tableModel.getItems()) {
            if (item.isLoaded()) {
                // 只处理非参数类的匹配规则
                if ("返回body".equals(item.getposition()) || "cookies".equals(item.getposition())) {
                    String content = "";

                    switch (item.getposition()) {
                        case "返回body":
                            content = new String(requestResponse.getResponse());
                            break;
                        case "cookies":
                            // 这里需要实现获取cookies的逻辑
                            break;
                    }

                    // 根据匹配方式进行匹配
                    boolean matchResult = false;
                    String matchedContent = ""; // 存储匹配到的内容

                    switch (item.getmethod()) {
                        case "正则表达式":
                            try {
                                Pattern pattern = Pattern.compile(item.getcontent());
                                Matcher matcher = pattern.matcher(content);
                                if (matcher.find()) {
                                    matchResult = true;
                                    matchedContent = matcher.group(); // 获取第一个匹配项
                                    // 继续查找更多匹配项并添加到结果中
                                    do {
                                        results.add(matcher.group());
                                    } while (matcher.find());
                                }
                            } catch (Exception e) {
                                System.err.println("Invalid regex pattern: " + item.getcontent());
                            }
                            break;
                        case "字符匹配":
                            matchResult = content.contains(item.getcontent());
                            if (matchResult) {
                                matchedContent = item.getcontent();
                                results.add(matchedContent);
                            }
                            break;
                    }
                }
            }
        }

        return results;
    }

    /**
     * 静态内部类用于存储匹配结果
     */
    private static class MatchResult {
        private String ruleName;
        private String paramName;
        private String paramValue;
        private String method;
        private String content;

        public MatchResult(String ruleName, String paramName, String paramValue, String method, String content) {
            this.ruleName = ruleName;
            this.paramName = paramName;
            this.paramValue = paramValue;
            this.method = method;
            this.content = content;
        }

        @Override
        public String toString() {
            return "Match found using rule '" + ruleName + "':\n" +
                   "Parameter: " + paramName + "=" + paramValue + "\n" +
                   "Rule: " + method + " - " + content + "\n" +
                   "-----------------------------";
        }
    }

    // 修改域名过滤规则为字符串包含匹配
    private boolean isAllowedDomain(String host) {
        //stdout.println("host:" + host);
        updateFilteredDomainsFromField();
        if (filteredDomains.isEmpty()) {
            return true;
        }else{
            for (String pattern : filteredDomains) {
                //stdout.println("peizhi:" + pattern.pattern());
                if (host.contains(pattern)) { // 使用字符串包含匹配
                    return true;
                }
            }
        }

        return false;
    }

    List<IScanIssue> processRequestResponse() {
        // 创建 Udatas 列表用于存储满足条件的请求内容
        //List<String> Udatas = new ArrayList<>();

        stdout.println("开始被动扫描处理");


        // 新增域名过滤检查
        IRequestInfo requestInfo_domain = helper.analyzeRequest(requestResponse);
        URL url_domain = requestInfo_domain.getUrl();
        //messageInfo = null;
        //url_domain.getHost()

        stdout.println("urlpath:"+ url_domain.getPath().toLowerCase());

        // 新增：排除以 .js 结尾的 URL
        if (url_domain.getPath().toLowerCase().endsWith(".js")) {
            stdout.println("js file cancle");
            return new ArrayList<>();
        }

        if (url_domain.getPath().toLowerCase().endsWith(".css")) {
            return new ArrayList<>();
        }

        if (url_domain.getPath().toLowerCase().endsWith(".png")) {
            return new ArrayList<>();
        }

        if (url_domain.getPath().toLowerCase().endsWith(".jpeg")) {
            return new ArrayList<>();
        }

        if (!isAllowedDomain(url_domain.getHost())) { // 调用修改后的域名检查方法
            return new ArrayList<>(); // 不在允许列表的域名直接返回空结果
        }

        // 新增OPTIONS方法过滤
        if ("OPTIONS".equalsIgnoreCase(requestInfo_domain.getMethod())) {
            return new ArrayList<>();
        }


        //URL url_domain = requestInfo.getUrl();
        //IRequestInfo requestInfo_domain = helper.analyzeRequest(requestResponse);
        //URL url_domain = requestInfo_domain.getUrl();
        //messageInfo = null;
        String domain = url_domain.getHost();

        for (IParameter param : requestInfo_domain.getParameters()) {
            // 只获取常见的POST body参数类型
            if (param.getType() == IParameter.PARAM_BODY ||
                    param.getType() == IParameter.PARAM_JSON ||
                    param.getType() == IParameter.PARAM_MULTIPART_ATTR ||
                    param.getType() == IParameter.PARAM_URL ||
                    param.getType() == IParameter.PARAM_XML){
                sendParamter(param,domain);
            }

            }





        boolean urlExists = false;

        synchronized (vulTable.Udatas) {
            for (VulTableModel data : vulTable.Udatas) {
                if (data.URL.equals(url_domain.toString())) {
                    urlExists = true;
                    break;
                }
            }
        }



        // 如果URL已经存在，则直接返回
        if (urlExists) {
            return new ArrayList<>();
        }



        String messege = "";

        // 处理非参数类的匹配
        List<String> nonParamResults = matchNonParameterContent();

        // 拼接非参数匹配结果
        if (!nonParamResults.isEmpty()) {
            String combinedResult = String.join("||", nonParamResults);
            stdout.println("Combined Non-Parameter Match Results: " + combinedResult);
            messege = messege + combinedResult + "\n";
        }

        // 使用新的匹配方法
        List<MatchResult> matchResults = matchParameters();

        // 处理匹配结果（可以根据需要实现具体的处理逻辑）
        for (MatchResult result : matchResults) {
            stdout.println(result.toString());

            // 构建请求内容字符串
            String requestContent = "Match found using rule '" + result.ruleName + "':\n" +
                                "Parameter: " + result.paramName + "=" + result.paramValue + "\n" +
                                "Rule: " + result.method + " - " + result.content + "\n" +
                                "-----------------------------";
            String requestContent_own = "Match found using rule '" + result.ruleName;
            messege = messege + requestContent_own + "\n";

            stdout.println(messege);

            if (!messege.isEmpty()){
                vulTable.addUrlFromProxy(requestResponse,messege);
            }

            // 将匹配结果添加到 Udatas
            //Udatas.add(requestContent);
        }
        return null;
    }
}
