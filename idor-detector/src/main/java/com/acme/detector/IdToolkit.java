package com.acme.detector;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * 对象编号(ID)的提取与替换。
 * 识别的 ID 形态:纯数字、带前缀编号(如 o-1001、inv-5001)、UUID;
 * 出现位置:URL 路径段、query 参数、JSON 请求体/响应体里键名以 id 结尾的字段。
 */
public final class IdToolkit {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final Pattern PATH_ID = Pattern.compile(
            "^([A-Za-z]+-)?\\d{3,}$|^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
    private static final Pattern ID_KEY = Pattern.compile("(?i).*(^|[_\\-])id$|^id$|.*Ids?$");
    private static final Pattern MARKER_KEY = Pattern.compile("(?i)^(email|phone|tenantId|number)$");

    private IdToolkit() {}

    /** 从请求(path + body)中提取对象编号;knownIds 里的值即使形态不像 ID 也算。 */
    public static Set<String> extractFromRequest(String path, String body, Set<String> knownIds) {
        Set<String> ids = new LinkedHashSet<>();
        // 路径段与 query 值
        for (String seg : path.split("[/?&=]")) {
            if (PATH_ID.matcher(seg).matches() || knownIds.contains(seg)) {
                ids.add(seg);
            }
        }
        // JSON 请求体里 *id 字段的值
        collectIdsFromJson(body, ids, null);
        return ids;
    }

    /** 从响应体中收集"这个账号可见"的对象编号与身份标识(作为受害方标记)。 */
    public static Set<String> harvestMarkers(String body) {
        Set<String> markers = new LinkedHashSet<>();
        collectIdsFromJson(body, markers, MARKER_KEY);
        return markers;
    }

    private static void collectIdsFromJson(String body, Set<String> out, Pattern extraKeyPattern) {
        if (body == null || body.isBlank()) return;
        try {
            JsonNode node = MAPPER.readTree(body);
            walk(node, out, extraKeyPattern);
        } catch (Exception ignored) {
            // 非 JSON 请求体,跳过
        }
    }

    private static void walk(JsonNode node, Set<String> out, Pattern extraKeyPattern) {
        if (node == null) return;
        if (node.isObject()) {
            node.fields().forEachRemaining(e -> {
                String key = e.getKey();
                JsonNode v = e.getValue();
                if (v.isValueNode() && (ID_KEY.matcher(key).matches()
                        || (extraKeyPattern != null && extraKeyPattern.matcher(key).matches()))) {
                    String text = v.asText();
                    if (text != null && text.length() >= 2 && text.length() <= 64) {
                        out.add(text);
                    }
                } else {
                    walk(v, out, extraKeyPattern);
                }
            });
        } else if (node.isArray()) {
            node.forEach(n -> walk(n, out, extraKeyPattern));
        }
    }

    /** 取 ID 的类型前缀:最后一个 "-" 之前(含),没有 "-" 则去掉尾部数字。 */
    public static String prefixOf(String id) {
        int i = id.lastIndexOf('-');
        if (i >= 0) {
            return id.substring(0, i + 1);
        }
        return id.replaceAll("\\d.*$", "");
    }

    /** 把 path/body 中的 oldId 全部换成 newId。 */
    public static String replace(String text, String oldId, String newId) {
        if (text == null) return null;
        return text.replace(oldId, newId);
    }
}
