import java.io.Serializable;

public record Message(String sign, String text, String key) implements Serializable {
}
