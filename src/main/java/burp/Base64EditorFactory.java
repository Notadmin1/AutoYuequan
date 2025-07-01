package burp;

import javax.swing.*;
import java.awt.*;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

// 实现工厂接口
public class Base64EditorFactory implements IMessageEditorTabFactory {
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;

    public Base64EditorFactory(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        return new Base64DecoderTab(controller, editable, helpers, stdout, stderr); // 为每个编辑器创建标签页实例
    }
}

// 自定义标签页实现
class Base64DecoderTab implements IMessageEditorTab {
    private final IExtensionHelpers helpers; // 新增成员变量
    private final JTextArea txtInput;
    private byte[] currentMessage;
    private boolean isEditable;
    private PrintWriter stdout;
    private PrintWriter stderr;

    public Base64DecoderTab(IMessageEditorController controller, boolean editable,IExtensionHelpers helpers,PrintWriter stdout, PrintWriter stderr) {
        this.helpers = helpers;
        this.isEditable = editable;
        this.txtInput = new JTextArea();
        this.txtInput.setFont(new Font("Monospaced", Font.PLAIN, 12));
        this.stdout = stdout;
        this.stderr = stderr;
    }

    // ================== 必须实现的接口方法 ==================
    @Override
    public String getTabCaption() {
        return "Base64 Decoder"; // 标签页标题
    }

    @Override
    public Component getUiComponent() {
        return new JScrollPane(txtInput); // 返回带滚动条的文本域
    }

    @Override
    public boolean isEnabled(byte[] content, boolean isRequest) {
        //return true;

        try {
            // 仅检测消息体中的Base64
            IRequestInfo requestInfo = helpers.analyzeRequest(content);
            int bodyOffset = requestInfo.getBodyOffset();
            String body = helpers.bytesToString(
                    Arrays.copyOfRange(content, bodyOffset, content.length)
            );

            //stdout.println("body:"+body);

            // 精确Base64检测正则（忽略大小写）
            String base64Pattern = "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$";
            return body.matches(base64Pattern);
        } catch (Exception e) {
            return false;
        }
    }


    @Override
    public void setMessage(byte[] content, boolean isRequest) {
        //stdout.println("content:"+new String(content));
        this.currentMessage = content;
        try {
            // 分离消息头与消息体
            IRequestInfo requestInfo = helpers.analyzeRequest(content);
            //List<String> headers = requestInfo.getHeaders();
            int bodyOffset = requestInfo.getBodyOffset();
            //stdout.println("body偏移量: " + bodyOffset + ", 总长度: " + content.length);

            //byte[] body = new byte[content.length - bodyOffset];
            // 安全校验body有效性
            if (bodyOffset >= content.length) {
                stdout.println("body偏移量超过数据长度");
                txtInput.setText("[空消息体]");
                return;
            }

            // 正确拷贝body数据
            int bodyLength = content.length - bodyOffset;
            byte[] body = Arrays.copyOfRange(content, bodyOffset, content.length);
            stdout.println("实际body长度: " + bodyLength);

            // 调试输出原始body内容
            stdout.println("原始body(HEX): " + bytesToHex(body));

            // 解码处理
            String decoded = new String(Base64.getDecoder().decode(body));
            txtInput.setText(decoded);

        } catch (Exception e) {
            txtInput.setText("[解码失败] " + e.getMessage());
        }
    }

    // HEX转换工具方法
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString().trim();
    }


    @Override
    public byte[] getMessage() {
        if (!isEditable) return currentMessage;

        try {
            // 保留原始消息头
            IRequestInfo requestInfo = helpers.analyzeRequest(currentMessage);
            List<String> headers = requestInfo.getHeaders();

            // 仅编码消息体
            String modifiedBody = txtInput.getText();
            byte[] encodedBody = Base64.getEncoder().encode(modifiedBody.getBytes());

            return helpers.buildHttpMessage(headers, encodedBody);
        } catch (Exception e) {
            return currentMessage;
        }
    }

    @Override
    public boolean isModified() {
        // 检测内容是否被修改
        try {
            String original = new String(Base64.getDecoder().decode(currentMessage));
            return !original.equals(txtInput.getText());
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public byte[] getSelectedData() {
        return new byte[0];
    }
}
