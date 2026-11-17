package com.acme.detector;

import com.acme.detector.Models.Account;
import com.acme.detector.Models.RecordedRequest;
import jakarta.inject.Inject;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/**
 * 一键演示数据:把指向本地靶场(localhost:8081)的三个账号
 * 和一组高权限账号录制的业务请求灌进平台。
 */
@Path("/api/demo")
@Produces(MediaType.APPLICATION_JSON)
public class DemoSeedResource {

    @Inject
    DetectorState state;

    @POST
    @Path("/seed")
    public Map<String, Object> seed() {
        String base = "http://localhost:8081";
        state.accounts.put("admin-a", new Account("admin-a", base,
                Map.of("X-Token", "token-admin-a"), "租户A 高权限(管理员)"));
        state.accounts.put("user-a", new Account("user-a", base,
                Map.of("X-Token", "token-user-a"), "租户A 低权限(普通用户)"));
        state.accounts.put("user-b", new Account("user-b", base,
                Map.of("X-Token", "token-user-b"), "租户B 普通用户(其他租户)"));

        state.recordings.clear();
        // 用高权限账号 admin-a 录一遍业务操作
        rec("GET", "/api/orders", null, "订单列表");
        rec("GET", "/api/orders/o-1001", null, "查看订单详情");
        rec("PUT", "/api/orders/o-1001/status?status=SHIPPED", null, "修改订单状态");
        rec("GET", "/api/invoices", null, "发票列表");
        rec("GET", "/api/invoices?ownerId=u-user-a", null, "按用户查发票");
        rec("GET", "/api/invoices/inv-5001", null, "查看发票详情");
        rec("GET", "/api/invoices/inv-5001/payments", null, "查看发票支付记录");
        rec("GET", "/api/documents", null, "文档列表");
        rec("GET", "/api/documents/d-9001", null, "查看文档");
        rec("GET", "/api/users/u-user-a", null, "查看用户资料");
        rec("GET", "/api/profile", null, "我的资料");
        rec("GET", "/api/audit-logs?userId=u-user-a", null, "查审计日志");

        return Map.of(
                "accounts", state.accounts.size(),
                "recordings", state.recordings.size(),
                "hint", "POST /api/scan {baselineAccount:'admin-a', lowPrivAccount:'user-a', crossTenantAccount:'user-b'}");
    }

    private void rec(String method, String path, String body, String note) {
        state.recordings.add(new RecordedRequest(
                UUID.randomUUID().toString().substring(0, 8),
                method, path, Map.of(), body, note, Instant.now()));
    }
}
