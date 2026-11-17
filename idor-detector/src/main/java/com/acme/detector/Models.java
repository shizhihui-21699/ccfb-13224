package com.acme.detector;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/** 检测平台领域模型。 */
public final class Models {

    /** 一个被测系统的账号(用请求头携带凭证)。 */
    public record Account(String name, String baseUrl, Map<String, String> headers, String note) {}

    /** 高权限账号录制下来的一条业务请求。 */
    public record RecordedRequest(
            String id,
            String method,
            String path,          // 含 query,例如 /api/orders/o-1001?x=1
            Map<String, String> headers,
            String body,
            String note,
            Instant recordedAt) {}

    public enum TestType {
        VERTICAL_REPLAY,        // 同租户低权限账号原样重放
        CROSS_TENANT_REPLAY,    // 其他租户账号原样重放
        ID_SUBSTITUTION         // 把请求中的对象编号换成受害方的再重放
    }

    public enum Verdict {
        VULNERABLE,      // 确认越权:拿到了不属于自己的数据
        SUSPICIOUS,      // 疑似:响应与基线部分相似,需人工复核
        SAFE_EMPTY,      // 返回空数据,未泄露
        SAFE_DENIED,     // 被拒绝(401/403/404)
        SAFE_DIFFERENT,  // 返回了内容但属于调用者自己的数据
        ERROR            // 重放本身失败(网络/5xx)
    }

    /** 一次重放的结果。 */
    public record ReplayResult(int status, String body, String error) {
        public boolean ok() {
            return error == null;
        }
    }

    /** 一条检测发现。 */
    public record Finding(
            String id,
            String endpointKey,      // 归组键: METHOD + 模板化路径
            TestType testType,
            String account,          // 用哪个账号重放的
            String recordedRequestId,
            String requestUrl,       // 实际重放的 URL(替换后)
            String substitutedId,    // ID 替换测试时换入的受害方对象编号,否则 null
            int status,
            int baselineStatus,
            double similarity,       // 与基线响应的相似度 0~1
            Verdict verdict,
            String evidence,         // 判定依据(人话)
            String baselineSnippet,
            String replaySnippet) {}

    /** 一次扫描的配置。 */
    public record ScanConfig(
            String baselineAccount,   // 高权限账号
            String lowPrivAccount,    // 同租户低权限账号
            String crossTenantAccount,// 其他租户账号
            double similarityThreshold) {}

    /** 一次扫描的完整结果。 */
    public record ScanResult(
            String id,
            ScanConfig config,
            Instant startedAt,
            Instant finishedAt,
            List<Finding> findings) {}

    /** 按接口归组后的报告条目。 */
    public record EndpointReport(
            String endpointKey,
            Verdict worstVerdict,
            long vulnerable,
            long suspicious,
            long safe,
            long error,
            List<Finding> findings) {}

    private Models() {}
}
