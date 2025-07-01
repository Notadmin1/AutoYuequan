package burp;

public class ParameterModel {
    final int Id;
    final String ParameterName;
    final String ParameterValue;
    final String ParameterType;
    String issue; // 移除 final 修饰符
    String domain;




    public ParameterModel(int id, String ParameterName, String ParameterValue, String ParameterType, String domain,String issue) {
        this.Id = id;
        this.ParameterName = ParameterName;
        this.ParameterValue = ParameterValue;
        this.ParameterType = ParameterType;
        this.issue = issue;
        this.domain = domain;
    }
}
