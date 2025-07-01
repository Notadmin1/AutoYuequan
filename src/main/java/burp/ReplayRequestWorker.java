package burp;

import javax.swing.*;
import java.nio.charset.StandardCharsets;
import java.util.List;

// 修改 ReplayRequestWorker_now 类以支持后台执行HTTP请求
public  class ReplayRequestWorker{
    /**
    private final IHttpRequestResponse originalRequestResponse;
    private IHttpRequestResponse ModifiedRequestResponse;
    private IHttpRequestResponse NoAuthRequestResponse;
    private final int selectedRow; // 新增：记录选中的行号

    public ReplayRequestWorker(IHttpRequestResponse originalRequestResponse, int selectedRow) { // 修改：增加selectedRow参数
        this.originalRequestResponse = originalRequestResponse;
        this.selectedRow = selectedRow; // 新增：初始化选中的行号
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
    **/
}
