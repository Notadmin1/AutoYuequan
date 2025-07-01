package burp;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class CustomContextMenu implements IContextMenuFactory {
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;
    private VulTable vulTable;

    public CustomContextMenu(IBurpExtenderCallbacks callbacks,VulTable vulTable) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(),true);
        this.stderr = new PrintWriter(callbacks.getStderr(),true);
        this.vulTable = vulTable;


    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menuItems = new ArrayList<>();

        // 1. 创建基础菜单项
        JMenuItem baseItem = new JMenuItem("yuequan");
        baseItem.addActionListener(new ContextMenuActionListener(invocation));


        // 2. 创建带图标的子菜单
        JMenu subMenu = new JMenu("高级功能");
        //subMenu.setIcon(new ImageIcon(getClass().getResource("/icon.png")));

        // 2.1 子菜单项-请求处理
        JMenuItem requestItem = new JMenuItem("处理请求");
        requestItem.addActionListener(e -> handleRequest(invocation));
        subMenu.add(requestItem);

        // 2.2 子菜单项-响应处理
        JMenuItem responseItem = new JMenuItem("处理响应");
        responseItem.addActionListener(e -> handleResponse(invocation));
        subMenu.add(responseItem);

        menuItems.add(baseItem);
        menuItems.add(subMenu);

        return menuItems;
    }


    public class ContextMenuActionListener implements ActionListener {
        IContextMenuInvocation invocation;

        public ContextMenuActionListener(IContextMenuInvocation invocation) {
            this.invocation = invocation;
        }

        @Override
        public void actionPerformed(ActionEvent actionEvent) {

            IHttpRequestResponse[] httpRequestResponses = invocation.getSelectedMessages();

            stdout.println("CustomContextMenu actionPerformed333:"+httpRequestResponses.toString());

            for (IHttpRequestResponse httpRequestResponse : httpRequestResponses) {
                stdout.println("CustomContextMenu actionPerformed4444:"+httpRequestResponse.toString());
                String issue = "From Proxy";
                vulTable.addUrlFromProxy(httpRequestResponse,issue);
            }
        }
    }



    private void processMessage(IHttpRequestResponse message) {

        stdout.println("CustomContextMenu actionPerformed333");
        // 实现具体消息处理逻辑
        byte[] request = message.getRequest();
        stdout.println("Modified Request: " + new String(request));
        //byte[] modifiedRequest = helpers.analyzeRequest(request).getRequest();
        // 获取请求头
        List<String> headers = helpers.analyzeRequest(request).getHeaders();

        // 遍历请求头，查找并修改Cookie
        for (int j = 0; j < headers.size(); j++) {
            if (headers.get(j).startsWith("Cookie:")) {
                // 修改Cookie信息
                headers.set(j, "Cookie: new_cookie_value=123456");
                break;
            }
        }
        //byte[] request = iHttpRequestResponse.getRequest();
        int bodyOffset = helpers.analyzeRequest(request).getBodyOffset();
        byte[] body = new byte[request.length - bodyOffset];

        byte[] modifiedRequest = helpers.buildHttpMessage(headers, body);
        //message.setRequest(modifiedRequest);
        IHttpRequestResponse modifiedResponse = callbacks.makeHttpRequest(message.getHttpService(), modifiedRequest);
        stdout.println("Modified Request: " + new String(modifiedRequest));
        //stdout.println("Modified Response: " + modifiedResponse.getResponse().toString());
    }

    private void handleRequest(IContextMenuInvocation invocation) {
        // 处理请求的扩展逻辑
    }

    private void handleResponse(IContextMenuInvocation invocation) {
        // 处理响应的扩展逻辑
    }
}

