package burp;

public class ConfigTableItemV2 {
    boolean loaded;
    String name;
    String position;
    String method;
    String content;
    //下面的参数没用，用来站位
    String color;
    String scope;
    String engine;
    boolean sensitive;

    public ConfigTableItemV2(boolean loaded, String name, String position, String method, String content) {
        this.loaded = loaded;
        this.name = name;
        this.position = position;
        this.method = method;
        this.content = content;

    }

    // Getters and Setters
    public boolean isLoaded() { return loaded; }
    public void setLoaded(boolean loaded) { this.loaded = loaded; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getposition() { return position; }
    public void setposition(String fRegex) { this.position = position; }
    public String getmethod() { return method; }
    public void setmethod(String sRegex) { this.method = method; }
    public String getcontent() { return content; }
    public void setcontent(String format) { this.content = content; }
}
