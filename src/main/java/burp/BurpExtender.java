package burp;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;

import javax.swing.*;
import java.io.PrintWriter;
//import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class BurpExtender implements IBurpExtender, IHttpListener {
    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;
    private PrintWriter stdout;
    private PrintWriter stderr;
    List<VulTableModel> Udatas = new ArrayList<>();

    /**
     * 实现 IBurpExtender 接口必须重写的核心方法，用于插件初始化
     *
     * @param iBurpExtenderCallbacks Burp 提供的回调接口，用于与 Burp 核心功能交互。
     *                               通过该参数可以访问所有 Burp API，
     *                               是插件功能的接入入口。
     * @return 无返回值
     */
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        /* 保存 Burp 回调接口的引用，后续操作都基于该引用 */
        this.callbacks = iBurpExtenderCallbacks;

        /* 设置插件在 Burp 界面中显示的名称 */
        callbacks.setExtensionName("first burp demo");

        /* 获取 HTTP 消息处理工具类实例，用于后续编解码等操作 */
        this.helpers = callbacks.getHelpers();

        /* 初始化标准输出/错误输出流，用于在 Burp 的 Extender 标签页显示信息 */
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);

        /* 在控制台输出初始化成功信息 */
        stdout.println("hello world");


        // 创建 BurpLikeUI 实例并添加到 Burp Suite 的 UI
        BurpLikeUI burpLikeUI = new BurpLikeUI(callbacks,Udatas);
        VulTable vulTable =burpLikeUI.getVulTable();
        //callbacks.addSuiteTab((ITab) burpLikeUI); // 添加到 Burp Suite 的 UI

        /* 重要：注册 HTTP 监听器（当前被注释）
           若需处理 HTTP 请求/响应，需取消注释并实现对应接口 */
        //callbacks.registerHttpListener(this);

        callbacks.registerScannerCheck(new MyScancheck(callbacks, burpLikeUI.configtable,vulTable, burpLikeUI.parameterModelTabel, burpLikeUI.urlpeizhiField));

        callbacks.registerContextMenuFactory(new CustomContextMenu(callbacks,vulTable));

        callbacks.registerMessageEditorTabFactory(new Base64EditorFactory(callbacks));
        callbacks.issueAlert("Base64 Editor Tab loaded!");
        stdout.println("Base64 Editor Tab loaded!");

        try {
            // 注册Payload工厂
            callbacks.registerIntruderPayloadGeneratorFactory(new SequentialPayloadFactory(callbacks));
            callbacks.printOutput("[关键] 自定义Payload工厂注册成功");
        } catch (Throwable t) { // 捕获所有异常，包括NoClassDefFoundError等
            callbacks.printError("注册失败: " + t.getClass().getName());
            t.printStackTrace(new PrintWriter(callbacks.getStderr()));
        }


    }

    @Override
    public void processHttpMessage(int i, boolean b, IHttpRequestResponse iHttpRequestResponse) {
        // 切换http监听模块为Burpsuiteproxy模块
        if (i == IBurpExtenderCallbacks.TOOL_REPEATER || i == IBurpExtenderCallbacks.TOOL_PROXY) {
            // 对请求包进行处理
            if (b) {
                // 对消息体进行解析
                IRequestInfo analyzeRequest = helpers.analyzeRequest(iHttpRequestResponse);

                // 获取请求头
                List<String> headers = analyzeRequest.getHeaders();

                // 遍历请求头，查找并修改Cookie
                for (int j = 0; j < headers.size(); j++) {
                    if (headers.get(j).startsWith("Cookie:")) {
                        // 修改Cookie信息
                        headers.set(j, "Cookie: new_cookie_value=123456");
                        break;
                    }
                }

                // 获取请求体
                byte[] request = iHttpRequestResponse.getRequest();
                int bodyOffset = analyzeRequest.getBodyOffset();
                byte[] body = new byte[request.length - bodyOffset];
                System.arraycopy(request, bodyOffset, body, 0, body.length);

                // 判断请求体是JSON还是键值对
                String bodyStr = new String(body);
                boolean isJson = false;
                try {
                    new org.json.JSONObject(bodyStr);
                    isJson = true;
                } catch (org.json.JSONException e) {
                    // 不是JSON格式
                }

                // 根据格式添加参数
                if (isJson) {
                    // JSON格式，添加新参数
                    org.json.JSONObject jsonBody = new org.json.JSONObject(bodyStr);
                    jsonBody.put("test", "1111");
                    bodyStr = jsonBody.toString();
                } else {
                    // 键值对格式，添加新参数
                    if (!bodyStr.isEmpty() && !bodyStr.endsWith("&")) {
                        bodyStr += "&";
                    }
                    bodyStr += "test=1111";
                }

                // 构建新的请求消息
                byte[] newRequest = helpers.buildHttpMessage(headers, bodyStr.getBytes());

                // 发送修改后的请求包
                iHttpRequestResponse.setRequest(newRequest);

                // 输出修改后的请求信息
                stdout.println("Modified Request: " + new String(newRequest));
            } else {
                // 处理响应包
                IResponseInfo analyzeResponse = helpers.analyzeResponse(iHttpRequestResponse.getResponse());

                // 获取响应码信息
                short statusCode = analyzeResponse.getStatusCode();
                stdout.println("Status Code: " + statusCode);

                // 获取响应头信息
                List<String> headers = analyzeResponse.getHeaders();
                for (String header : headers) {
                    stdout.println("Response Header: " + header);
                }

                // 获取响应体信息
                byte[] response = iHttpRequestResponse.getResponse();
                int bodyOffset = analyzeResponse.getBodyOffset();
                byte[] body = new byte[response.length - bodyOffset];
                System.arraycopy(response, bodyOffset, body, 0, body.length);

                // 输出修改后的响应信息
                stdout.println("Modified Response: " + new String(response));
            }
        }
    }

    //@Override
    public void processHttpMessage111(int i, boolean b, IHttpRequestResponse iHttpRequestResponse) {
        //切换http监听模块为Burpsuiteproxy模块
        if (i == IBurpExtenderCallbacks.TOOL_REPEATER || i == IBurpExtenderCallbacks.TOOL_PROXY) {
            //对请求包进行处理
            if (b) {
                //对消息体进行解析,messageInfo是整个HTTP请求和响应消息体的总和，各种HTTP相关信息的获取都来自于它，HTTP流量的修改都是围绕它进行的。
                IRequestInfo analyzeRequest = helpers.analyzeRequest(iHttpRequestResponse);
                /*****************获取参数**********************/
                List<IParameter> parameList = analyzeRequest.getParameters();
                //获取参数的方法
                //遍历参数
                for (IParameter para : parameList) {
                    //获取参数
                    String key = para.getName();
                    //获取参数值(value)
                    String value = para.getValue();
                    int type = para.getType();
                    stdout.println("参数key value type:" + key + " " + value + " " + type);
                }

                //获取headers方法:
                List<String> headers = analyzeRequest.getHeaders();
                //新增header
                headers.add("myheader:hello world");
                //遍历请求头
                for (String header : headers) {
                    stdout.println("header: " + header);
                }

                //获取协议 端口 和主机名
                IHttpService service = iHttpRequestResponse.getHttpService();
                stdout.println("协议 主机 端口 " + service.getProtocol() + " " + service.getHost() + " " + service.getPort());
            }

        } else {//这个逻辑是处理响应包
            IResponseInfo analyzeResponse = helpers.analyzeResponse(iHttpRequestResponse.getResponse());
            //获取响应码信息
            short statusCode = analyzeResponse.getStatusCode();
            stdout.println("status= " + statusCode);
            //获取响应头信息
            List<String> headers = analyzeResponse.getHeaders();
            for (String header : headers) {
                stdout.println("header:" + header);
            }
            // 获取响应信息
            String resp = new String(iHttpRequestResponse.getResponse());
            int bodyOffset = analyzeResponse.getBodyOffset();
            String body = resp.substring(bodyOffset);
            stdout.println("response body=" + body);
        }
    }
}