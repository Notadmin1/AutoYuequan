package burp;

import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

public class SequentialPayloadFactory implements IIntruderPayloadGeneratorFactory {
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;

    public SequentialPayloadFactory(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.printOutput("顺序载荷工厂初始化完成");
        String[] versionInfo = callbacks.getBurpVersion();
        String versionStr = String.join(".", versionInfo);
        callbacks.printOutput("当前Burp版本: " + versionStr);
    }

    @Override
    public String getGeneratorName() {
        return "Sequential Number Payload";
    }

    // SequentialPayloadFactory.java
    @Override
    public IIntruderPayloadGenerator createNewInstance(IIntruderAttack attack) {
        callbacks.printOutput("生成器实例化开始");
        return new SequentialPayloadGenerator();
    }

    private static class SequentialPayloadGenerator implements IIntruderPayloadGenerator {
        private int index = 1;
        private final int maxPayloads = 1000;

        @Override
        public byte[] getNextPayload(byte[] baseValue) {
            return ("PAYLOAD-" + index++).getBytes(StandardCharsets.UTF_8);
        }

        @Override
        public boolean hasMorePayloads() {
            return true; // 简化为无限生成
        }

        @Override
        public void reset() {
            index = 1;
        }
    }

}
