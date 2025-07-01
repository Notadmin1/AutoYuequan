package burp;

import javax.swing.*;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MRquest  extends SwingWorker<IHttpRequestResponse[], Void>{

    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;
    private PrintWriter stdout;
    private PrintWriter stderr;
    private java.util.Properties headerConfig;
    private  Vultableextend vtable;
    private List<Pattern> sensitivePatterns = new ArrayList<>();
    private List<Pattern> paramNamePatterns = new ArrayList<>(); // 替换原Pattern类型变量
    private List<Pattern> filteredDomains = new ArrayList<>(); // 新增域名过滤配置变量
    private String  messageInfo = "";
    private List<VulTableModel> Udatas;


    private final IHttpRequestResponse originalRequestResponse;
    private IHttpRequestResponse ModifiedRequestResponse;
    private IHttpRequestResponse NoAuthRequestResponse;
    private final int selectedRow; // 新增：记录选中的行号

    private JTextArea newHeaderField;
    private JTextArea lowHeaderField;


    public MRquest(IBurpExtenderCallbacks callbacks, java.util.Properties headerConfig, Vultableextend vtable,IHttpRequestResponse originalRequestResponse, int selectedRow, List<VulTableModel> Udatas,JTextArea newHeaderField,JTextArea lowHeaderField) {
        this.callbacks = callbacks;
        //this.headerConfig = headerConfig;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        this.vtable = vtable;
        this.originalRequestResponse = originalRequestResponse;
        this.selectedRow = selectedRow;
        this.Udatas = Udatas;

        this.newHeaderField = newHeaderField;
        this.lowHeaderField = lowHeaderField;

        // 新增默认值回退逻辑
        if (sensitivePatterns.isEmpty()) {
            sensitivePatterns.add(Pattern.compile("\\b\\d{3}-\\d{8}\\b")); // 身份证号
            sensitivePatterns.add(Pattern.compile("\\b\\d{11}\\b")); // 手机号
            sensitivePatterns.add(Pattern.compile("\\b[\\w.-]+@[\\w.-]+\\.\\w+\\b")); // 邮箱
        }
    }



    public Map<String, String> GetNewHeaderField() {
        //测试水平
        Map<String, String> headers = new HashMap<>();

        // 处理newHeaderField
        if (newHeaderField != null && !newHeaderField.getText().trim().isEmpty()) {
            String[] newHeaders = newHeaderField.getText().trim().split("\\n");
            for (String header : newHeaders) {
                String[] parts = header.trim().split(":", 2);
                if (parts.length == 2) {
                    headers.put(parts[0].trim(), parts[1].trim());
                } else {
                    headers.put(parts[0].trim(), "");
                }
            }
        }
        return headers;
    }


    public Map<String, String> GetLowHeaderField() {
        Map<String, String> headers = new HashMap<>();
        // 处理lowHeaderField
        if (lowHeaderField != null && !lowHeaderField.getText().trim().isEmpty()) {
            String[] lowHeaders = lowHeaderField.getText().trim().split("\\n");
            for (String header : lowHeaders) {
                String[] parts = header.trim().split(":", 2);
                if (parts.length == 2) {
                    headers.put(parts[0].trim(), parts[1].trim());
                } else {
                    headers.put(parts[0].trim(), "");
                }
            }
        }

        return headers;
    }



    private byte[] modifyHeaders_old(byte[] request) {
        stdout.println("modifyHeaders: Starting to modify headers111.");
        try {
            Map<String, String> GetheaderConfig = GetNewHeaderField();
            IRequestInfo requestInfo = helpers.analyzeRequest(request);
            if (requestInfo == null) {
                stdout.println("Error: Failed to analyze request.");
                return request; // 返回原始请求
            }

            List<String> headers = requestInfo.getHeaders();
            if (headers == null || headers.isEmpty()) {
                stdout.println("Warning: No headers found in the request.");
                return request;
            }

            List<String> newHeaders = new ArrayList<>();

            // 保留原有的header头，除非被配置覆盖
            for (String header : headers) {
                if (!headerConfig.containsKey(extractHeaderKey(header))) {
                    newHeaders.add(header);
                }
            }

            // 遍历配置中的header头，添加到请求中（不放在第一行）
            for (String key : headerConfig.stringPropertyNames()) {
                newHeaders.add(key + ": " + headerConfig.getProperty(key));
            }

            // 获取请求体
            int bodyOffset = requestInfo.getBodyOffset();
            byte[] body = new byte[request.length - bodyOffset];
            System.arraycopy(request, bodyOffset, body, 0, body.length);

            // 重建请求
            byte[] modifiedRequest = helpers.buildHttpMessage(newHeaders, body);
            stdout.println("modifyHeaders: Modified request successfully.");
            return modifiedRequest;

        } catch (Exception e) {
            stdout.println("Exception in modifyHeaders: " + e.getMessage());
            e.printStackTrace(new PrintWriter(callbacks.getStderr()));
            return request; // 返回原始请求以防崩溃
        }
    }

    private byte[] modifyHeaders(byte[] request) {
        stdout.println("modifyHeaders: Starting to modify headers.");
        try {

            IRequestInfo requestInfo = helpers.analyzeRequest(request);
            if (requestInfo == null) {
                stdout.println("Error: Failed to analyze request.");
                return request; // 返回原始请求
            }

            List<String> headers = requestInfo.getHeaders();
            if (headers == null || headers.isEmpty()) {
                stdout.println("Warning: No headers found in the request.");
                return request;
            }

            List<String> newHeaders = new ArrayList<>();

            // 保留原有的header头，除非被GetNewHeaderField覆盖
            Map<String, String> newHeaderMap = GetNewHeaderField(); // 获取新的Header Map

            for (String header : headers) {
                String key = extractHeaderKey(header);
                // 如果新Header Map不包含当前header的键，则保留它
                if (!newHeaderMap.containsKey(key)) {
                    newHeaders.add(header);
                }
            }

            // 将GetNewHeaderField中的header添加进请求头中
            for (Map.Entry<String, String> entry : newHeaderMap.entrySet()) {
                newHeaders.add(entry.getKey() + ": " + entry.getValue());
            }

            // 获取请求体
            int bodyOffset = requestInfo.getBodyOffset();
            byte[] body = new byte[request.length - bodyOffset];
            System.arraycopy(request, bodyOffset, body, 0, body.length);

            // 重建请求
            byte[] modifiedRequest = helpers.buildHttpMessage(newHeaders, body);
            stdout.println("modifyHeaders: Modified request successfully.");
            return modifiedRequest;

        } catch (Exception e) {
            stdout.println("Exception in modifyHeaders: " + e.getMessage());
            e.printStackTrace(new PrintWriter(callbacks.getStderr()));
            return request; // 返回原始请求以防崩溃
        }
    }






    // 辅助方法：提取 header 的键名
    private String extractHeaderKey(String header) {
        if (header != null && header.contains(":")) {
            return header.split(":", 2)[0].trim();
        }
        return header.trim(); // 如果没有冒号，则返回原字符串
    }


    private  byte[] RemoveHeaders(byte[] request) {
        stdout.print("RemoveHeaders");
        IRequestInfo requestInfo = helpers.analyzeRequest(request);
        List<String> headers = requestInfo.getHeaders();
        List<String> newHeaders = new ArrayList<>();

        // 保留原有的header头，除非被配置覆盖
        /**
        for (String header : headers) {
            if (!headerConfig.containsKey(header.split(":")[0])) {
                newHeaders.add(header);
            }
        }**/


        // 保留原有的header头，除非被GetNewHeaderField覆盖
        Map<String, String> newHeaderMap = GetNewHeaderField(); // 获取新的Header Map

        for (String header : headers) {
            String key = extractHeaderKey(header);
            // 如果新Header Map不包含当前header的键，则保留它
            if (!newHeaderMap.containsKey(key)) {
                newHeaders.add(header);
            }
        }

        // 遍历配置中的header头，添加到请求中（不放在第一行）

        //for (String key : headerConfig.stringPropertyNames()) {
        //    newHeaders.add(key + ": " + headerConfig.getProperty(key));
        //}

        // 获取请求体
        int bodyOffset = requestInfo.getBodyOffset();
        byte[] body = new byte[request.length - bodyOffset];
        System.arraycopy(request, bodyOffset, body, 0, body.length);

        // 重建请求
        return helpers.buildHttpMessage(newHeaders, body);
    }


    // 新增方法：计算两个字符串的相似度（这里使用Jaccard相似度作为示例）
    private double calculateSimilarity(String str1, String str2) {
        Set<String> set1 = new HashSet<>(Arrays.asList(str1.split("\\s+")));
        Set<String> set2 = new HashSet<>(Arrays.asList(str2.split("\\s+")));

        Set<String> intersection = new HashSet<>(set1);
        intersection.retainAll(set2);

        Set<String> union = new HashSet<>(set1);
        union.addAll(set2);

        return (double) intersection.size() / union.size();
    }


    // 检测响应是否包含敏感信息的方法
    private boolean checkResponseForSensitive(byte[] response) {
        IResponseInfo responseInfo = helpers.analyzeResponse(response);
        if (responseInfo.getStatusCode() != 200) {
            return false;
        }
        int bodyOffset = responseInfo.getBodyOffset();
        if (bodyOffset >= response.length) {
            return false;
        }
        String resp = new String(response);
        String bodyStr = resp.substring(bodyOffset);
        for (Pattern pattern : sensitivePatterns) {
            Matcher matcher = pattern.matcher(bodyStr);
            if (matcher.find()) { // 先检查是否有匹配项
                messageInfo = messageInfo + "sensitive: " + matcher.group() + "\n";
                return true;
            }
        }
        return false;
    }


    // 新增方法：提取响应中的敏感信息
    private List<String> extractSensitiveInfo(byte[] response) {
        List<String> sensitiveInfoList = new ArrayList<>();
        IResponseInfo responseInfo = helpers.analyzeResponse(response);
        int bodyOffset = responseInfo.getBodyOffset();
        String bodyStr = new String(response, StandardCharsets.UTF_8).substring(bodyOffset);

        for (Pattern pattern : sensitivePatterns) {
            Matcher matcher = pattern.matcher(bodyStr);
            while (matcher.find()) {
                sensitiveInfoList.add(matcher.group());
            }
        }
        return sensitiveInfoList;
    }


    @Override
    protected IHttpRequestResponse[] doInBackground() throws Exception {
        stdout.println("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^");

        String newHeaderField1 =newHeaderField.getText();
        stdout.println("newHeaderField1: " + newHeaderField1);
        //IMessageEditorController originalRequestResponse;
        byte[] originalRequest = originalRequestResponse.getRequest();

        stdout.println("originalRequest: " + new String(originalRequest));

        // 第一次请求：使用 modifyHeaders 方法修改请求头
        byte[] modifiedRequest = modifyHeaders(originalRequest);

        stdout.println("modifiedRequest: " + new String(modifiedRequest));
        ModifiedRequestResponse = callbacks.makeHttpRequest(
                originalRequestResponse.getHttpService(),
                modifiedRequest
        );

        // 第二次请求：使用 RemoveHeaders 方法移除特定请求头
        byte[] RemoveRequest = RemoveHeaders(originalRequest);
        NoAuthRequestResponse = callbacks.makeHttpRequest(
                originalRequestResponse.getHttpService(),
                RemoveRequest
        );

        // 返回所需的值
        return new IHttpRequestResponse[]{ModifiedRequestResponse, NoAuthRequestResponse};
    }

    @Override
    protected void done() {
        try {
            IHttpRequestResponse[] results = get();
            IHttpRequestResponse replayedResponse = results[0];
            IHttpRequestResponse RmovereplayedResponse = results[1];
            stdout.println("replayedResponse: " + replayedResponse.toString());
            stdout.println("RmovereplayedResponse: " + RmovereplayedResponse.toString());

            // 获取原始响应和修改后响应的body
            String originalResponseBody = new String(originalRequestResponse.getResponse(), StandardCharsets.UTF_8);
            String replayedResponseBody = new String(replayedResponse.getResponse(), StandardCharsets.UTF_8);
            String RmovereplayedResponseBody = new String(RmovereplayedResponse.getResponse(), StandardCharsets.UTF_8);

            // 提取body部分
            IResponseInfo originalResponseInfo = helpers.analyzeResponse(originalRequestResponse.getResponse());
            IResponseInfo replayedResponseInfo = helpers.analyzeResponse(replayedResponse.getResponse());
            IResponseInfo RmovereplayedResponseInfo = helpers.analyzeResponse(RmovereplayedResponse.getResponse());
            int originalBodyOffset = originalResponseInfo.getBodyOffset();
            int replayedBodyOffset = replayedResponseInfo.getBodyOffset();
            int RmovereplayedBodyOffset = RmovereplayedResponseInfo.getBodyOffset();

            String originalBody = originalResponseBody.substring(originalBodyOffset);
            String replayedBody = replayedResponseBody.substring(replayedBodyOffset);
            String RmovereplayedBody = RmovereplayedResponseBody.substring(RmovereplayedBodyOffset);

            // 计算相似度
            double similarity = calculateSimilarity(originalBody, replayedBody);
            stdout.println("Similarity between original and modified response bodies: " + similarity);

            double Rmovesimilarity = calculateSimilarity(originalBody, RmovereplayedBody);
            stdout.println("Similarity between original and modified response bodies (RemoveHeaders): " + Rmovesimilarity);

            // 检查原始响应body是否包含敏感信息
            boolean originalHasSensitive = checkResponseForSensitive(originalRequestResponse.getResponse());
            String ShuipingSentivite = "No";
            String NoAuthSentivite = "No";
            if (originalHasSensitive) {
                stdout.println("Original response contains sensitive information.");
                // 检查修改后响应body是否包含敏感信息
                boolean replayedHasSensitive = checkResponseForSensitive(replayedResponse.getResponse());
                if (replayedHasSensitive) {
                    stdout.println("Modified response also contains sensitive information.");
                    List<String> originalSensitiveInfo = extractSensitiveInfo(originalRequestResponse.getResponse());
                    List<String> replayedSensitiveInfo = extractSensitiveInfo(replayedResponse.getResponse());
                    boolean isSensitiveInfoSame = originalSensitiveInfo.equals(replayedSensitiveInfo);
                    // 更新 ShuipingSentivite 字段
                    ShuipingSentivite = isSensitiveInfoSame ? "Yes" : "No";
                } else {
                    stdout.println("Modified response does not contain sensitive information.");
                }
                boolean RmovereplayedHasSensitive = checkResponseForSensitive(RmovereplayedResponse.getResponse());
                if (RmovereplayedHasSensitive) {
                    stdout.println("Modified response (RemoveHeaders) also contains sensitive information.");
                    List<String> originalSensitiveInfo = extractSensitiveInfo(originalRequestResponse.getResponse());
                    List<String> RmovereplayedSensitiveInfo = extractSensitiveInfo(RmovereplayedResponse.getResponse());
                    boolean isSensitiveInfoSame = originalSensitiveInfo.equals(RmovereplayedSensitiveInfo);
                    NoAuthSentivite = isSensitiveInfoSame ? "Yes" : "No";
                }
            }

            // 更新 ShuipingSimilarity 和 NoAuthSimilarity 字段
            int ShuipingSimilarity = (int) (similarity * 100); // 将相似度转换为百分比
            int NoAuthSimilarity = (int) (Rmovesimilarity * 100);
            String issue = "已经重放";

            // 直接修改 dataEntry 的值
            if (selectedRow != -1) {
                int modelRow = vtable.convertRowIndexToModel(selectedRow);
                VulTableModel dataEntry = Udatas.get(modelRow);
                dataEntry.ModifiedRequestResponse = ModifiedRequestResponse;
                dataEntry.NoAuthRequestResponse = NoAuthRequestResponse;
                dataEntry.ShuipingSentivite = ShuipingSentivite;
                dataEntry.NoAuthSentivite = NoAuthSentivite;
                dataEntry.ShuipingSimilarity = ShuipingSimilarity;
                dataEntry.NoAuthSimilarity = NoAuthSimilarity;
                dataEntry.Replay = issue;
                vtable.repaint();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}



/**

    // 修改 ReplayRequestWorker_now 类以支持后台执行HTTP请求
    public static class ReplayRequestWorker_now extends SwingWorker<IHttpRequestResponse[], Void> {
        private final IHttpRequestResponse originalRequestResponse;
        private IHttpRequestResponse ModifiedRequestResponse;
        private IHttpRequestResponse NoAuthRequestResponse;
        private final int selectedRow; // 新增：记录选中的行号
        //private IBurpExtenderCallbacks callbacks;

        public ReplayRequestWorker_now(IHttpRequestResponse originalRequestResponse, int selectedRow,IBurpExtenderCallbacks callbacks) { // 修改：增加selectedRow参数
            this.originalRequestResponse = originalRequestResponse;
            this.selectedRow = selectedRow; // 新增：初始化选中的行号
            //this.callbacks = callbacks;
        }

        @Override
        protected IHttpRequestResponse[] doInBackground() throws Exception {
            byte[] originalRequest = originalRequestResponse.getRequest();

            // 第一次请求：使用 modifyHeaders 方法修改请求头
            byte[] modifiedRequest = modifyHeaders(originalRequest);
            ModifiedRequestResponse = callbacks.makeHttpRequest(
                    originalRequestResponse.getHttpService(),
                    modifiedRequest
            );

            // 第二次请求：使用 RemoveHeaders 方法移除特定请求头
            byte[] RemoveRequest = RemoveHeaders(originalRequest);
            NoAuthRequestResponse = callbacks.makeHttpRequest(
                    originalRequestResponse.getHttpService(),
                    RemoveRequest
            );

            // 返回所需的值
            return new IHttpRequestResponse[]{ModifiedRequestResponse, NoAuthRequestResponse};
        }

        @Override
        protected void done() {
            try {
                IHttpRequestResponse[] results = get();
                IHttpRequestResponse replayedResponse = results[0];
                IHttpRequestResponse RmovereplayedResponse = results[1];

                // 获取原始响应和修改后响应的body
                String originalResponseBody = new String(originalRequestResponse.getResponse(), StandardCharsets.UTF_8);
                String replayedResponseBody = new String(replayedResponse.getResponse(), StandardCharsets.UTF_8);
                String RmovereplayedResponseBody = new String(RmovereplayedResponse.getResponse(), StandardCharsets.UTF_8);

                // 提取body部分
                IResponseInfo originalResponseInfo = helpers.analyzeResponse(originalRequestResponse.getResponse());
                IResponseInfo replayedResponseInfo = helpers.analyzeResponse(replayedResponse.getResponse());
                IResponseInfo RmovereplayedResponseInfo = helpers.analyzeResponse(RmovereplayedResponse.getResponse());
                int originalBodyOffset = originalResponseInfo.getBodyOffset();
                int replayedBodyOffset = replayedResponseInfo.getBodyOffset();
                int RmovereplayedBodyOffset = RmovereplayedResponseInfo.getBodyOffset();

                String originalBody = originalResponseBody.substring(originalBodyOffset);
                String replayedBody = replayedResponseBody.substring(replayedBodyOffset);
                String RmovereplayedBody = RmovereplayedResponseBody.substring(RmovereplayedBodyOffset);

                // 计算相似度
                double similarity = calculateSimilarity(originalBody, replayedBody);
                stdout.println("Similarity between original and modified response bodies: " + similarity);

                double Rmovesimilarity = calculateSimilarity(originalBody, RmovereplayedBody);
                stdout.println("Similarity between original and modified response bodies (RemoveHeaders): " + Rmovesimilarity);

                // 检查原始响应body是否包含敏感信息
                boolean originalHasSensitive = checkResponseForSensitive(originalRequestResponse.getResponse());
                String ShuipingSentivite = "No";
                String NoAuthSentivite = "No";
                if (originalHasSensitive) {
                    stdout.println("Original response contains sensitive information.");
                    // 检查修改后响应body是否包含敏感信息
                    boolean replayedHasSensitive = checkResponseForSensitive(replayedResponse.getResponse());
                    if (replayedHasSensitive) {
                        stdout.println("Modified response also contains sensitive information.");
                        List<String> originalSensitiveInfo = extractSensitiveInfo(originalRequestResponse.getResponse());
                        List<String> replayedSensitiveInfo = extractSensitiveInfo(replayedResponse.getResponse());
                        boolean isSensitiveInfoSame = originalSensitiveInfo.equals(replayedSensitiveInfo);
                        // 更新 ShuipingSentivite 字段
                        ShuipingSentivite = isSensitiveInfoSame ? "Yes" : "No";
                    } else {
                        stdout.println("Modified response does not contain sensitive information.");
                    }
                    boolean RmovereplayedHasSensitive = checkResponseForSensitive(RmovereplayedResponse.getResponse());
                    if (RmovereplayedHasSensitive) {
                        stdout.println("Modified response (RemoveHeaders) also contains sensitive information.");
                        List<String> originalSensitiveInfo = extractSensitiveInfo(originalRequestResponse.getResponse());
                        List<String> RmovereplayedSensitiveInfo = extractSensitiveInfo(RmovereplayedResponse.getResponse());
                        boolean isSensitiveInfoSame = originalSensitiveInfo.equals(RmovereplayedSensitiveInfo);
                        NoAuthSentivite = isSensitiveInfoSame ? "Yes" : "No";
                    }
                }

                // 更新 ShuipingSimilarity 和 NoAuthSimilarity 字段
                int ShuipingSimilarity = (int) (similarity * 100); // 将相似度转换为百分比
                int NoAuthSimilarity = (int) (Rmovesimilarity * 100);
                String issue = "已经重放";

                // 直接修改 dataEntry 的值
                if (selectedRow != -1) {
                    int modelRow = vtable.convertRowIndexToModel(selectedRow);
                    VulTableModel dataEntry = Udatas.get(modelRow);
                    dataEntry.ModifiedRequestResponse = ModifiedRequestResponse;
                    dataEntry.NoAuthRequestResponse = NoAuthRequestResponse;
                    dataEntry.ShuipingSentivite = ShuipingSentivite;
                    dataEntry.NoAuthSentivite = NoAuthSentivite;
                    dataEntry.ShuipingSimilarity = ShuipingSimilarity;
                    dataEntry.NoAuthSimilarity = NoAuthSimilarity;
                    dataEntry.Replay = issue;
                    vtable.repaint();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }**/
