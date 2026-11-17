package com.acme.detector;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * 响应比对:
 *  1. 归一化 —— JSON 排序键、剔除易变字段(时间戳/请求ID等),非 JSON 则原样裁剪;
 *  2. 相似度 —— 对归一化文本的 token 多重集计算 Dice 系数,0~1。
 */
@ApplicationScoped
public class ComparatorService {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** 易变字段名(小写匹配),比对前剔除。 */
    private static final List<String> VOLATILE_KEYS = List.of(
            "timestamp", "createdat", "updatedat", "requestid", "traceid",
            "token", "sessionid", "date", "time", "nonce");

    /** 归一化响应体:能解析成 JSON 就去易变字段 + 键排序,否则截断原文。 */
    public String normalize(String body) {
        if (body == null) return "";
        String trimmed = body.trim();
        if (trimmed.isEmpty()) return "";
        try {
            JsonNode node = MAPPER.readTree(trimmed);
            JsonNode cleaned = stripVolatile(node);
            return MAPPER.writeValueAsString(sorted(cleaned));
        } catch (Exception e) {
            return trimmed.length() > 4096 ? trimmed.substring(0, 4096) : trimmed;
        }
    }

    private JsonNode stripVolatile(JsonNode node) {
        if (node instanceof ObjectNode obj) {
            List<String> toRemove = new ArrayList<>();
            obj.fieldNames().forEachRemaining(name -> {
                if (VOLATILE_KEYS.contains(name.toLowerCase())) {
                    toRemove.add(name);
                }
            });
            toRemove.forEach(obj::remove);
            obj.fields().forEachRemaining(e -> stripVolatile(e.getValue()));
        } else if (node.isArray()) {
            node.forEach(this::stripVolatile);
        }
        return node;
    }

    /** 递归把 ObjectNode 的键排序,保证同样内容序列化结果一致。 */
    private JsonNode sorted(JsonNode node) {
        if (node instanceof ObjectNode obj) {
            Map<String, JsonNode> map = new TreeMap<>();
            obj.fields().forEachRemaining(e -> map.put(e.getKey(), sorted(e.getValue())));
            ObjectNode out = MAPPER.createObjectNode();
            map.forEach(out::set);
            return out;
        }
        if (node.isArray()) {
            var arr = MAPPER.createArrayNode();
            node.forEach(n -> arr.add(sorted(n)));
            return arr;
        }
        return node;
    }

    /**
     * Dice 系数:2|A∩B| / (|A|+|B|)。
     * token 取 JSON 叶子的 "键=值" 对 —— 越权关心的是"拿到了同样的数据",
     * 而不是同样的 JSON 结构;非 JSON 退化为按词切分。
     */
    public double similarity(String normalizedA, String normalizedB) {
        if (normalizedA.isEmpty() && normalizedB.isEmpty()) return 1.0;
        if (normalizedA.isEmpty() || normalizedB.isEmpty()) return 0.0;
        Map<String, Integer> a = tokens(normalizedA);
        Map<String, Integer> b = tokens(normalizedB);
        long common = 0;
        for (var e : a.entrySet()) {
            common += Math.min(e.getValue(), b.getOrDefault(e.getKey(), 0));
        }
        long total = a.values().stream().mapToLong(i -> i).sum()
                + b.values().stream().mapToLong(i -> i).sum();
        return total == 0 ? 1.0 : (2.0 * common) / total;
    }

    private Map<String, Integer> tokens(String normalized) {
        Map<String, Integer> map = new HashMap<>();
        try {
            JsonNode node = MAPPER.readTree(normalized);
            collectLeafPairs(node, null, map);
        } catch (Exception e) {
            for (String t : normalized.split("[^\\p{IsAlphabetic}\\p{IsDigit}]+")) {
                if (!t.isEmpty()) {
                    map.merge(t, 1, Integer::sum);
                }
            }
        }
        return map;
    }

    /** 收集叶子键值对:对象字段取 "键=值",基本类型数组取 "父键=值",根基本类型取值本身。 */
    private void collectLeafPairs(JsonNode node, String parentKey, Map<String, Integer> out) {
        if (node == null || node.isNull() || node.isMissingNode()) return;
        if (node.isObject()) {
            node.fields().forEachRemaining(e -> collectLeafPairs(e.getValue(), e.getKey(), out));
        } else if (node.isArray()) {
            node.forEach(n -> collectLeafPairs(n, parentKey, out));
        } else {
            String token = parentKey != null ? parentKey + "=" + node.asText() : node.asText();
            out.merge(token, 1, Integer::sum);
        }
    }

    /** 空数据判定:空串、空 JSON 对象/数组、null。 */
    public boolean isEmptyData(String body) {
        if (body == null) return true;
        String t = body.trim();
        return t.isEmpty() || t.equals("{}") || t.equals("[]") || t.equals("null") || t.equals("\"\"");
    }

    /** 响应里是否出现了受害方标识(对象编号、邮箱等)。 */
    public List<String> matchedMarkers(String body, Iterable<String> markers) {
        List<String> hits = new ArrayList<>();
        if (body == null) return hits;
        for (String m : markers) {
            if (m != null && m.length() >= 3 && body.contains(m)) {
                hits.add(m);
            }
        }
        return hits;
    }
}
