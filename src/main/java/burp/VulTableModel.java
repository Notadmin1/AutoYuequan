package burp;

public class VulTableModel {
    final int Id;
    final String Method;
    final String URL;
    final String Status;
    String issue; // 移除 final 修饰符
    final IHttpRequestResponse requestResponse;
    String ShuipingSentivite;
    String NoAuthSentivite;
    int ShuipingSimilarity;
    int NoAuthSimilarity;
    IHttpRequestResponse ModifiedRequestResponse = null;
    IHttpRequestResponse NoAuthRequestResponse = null;
    String Replay = "未检测";


    public VulTableModel(int id, String method, String url, String status, String issue, IHttpRequestResponse requestResponse) {
        this.Id = id;
        this.Method = method;
        this.URL = url;
        this.Status = status;
        this.issue = issue;
        this.requestResponse = requestResponse;
        this.ShuipingSentivite = "";
        this.NoAuthSentivite = "";
        this.NoAuthSimilarity = 0;
        this.ShuipingSimilarity = 0;
    }
}
