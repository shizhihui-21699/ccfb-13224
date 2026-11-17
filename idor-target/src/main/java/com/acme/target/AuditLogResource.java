package com.acme.target;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import java.util.List;

@Path("/api/audit-logs")
@Produces(MediaType.APPLICATION_JSON)
public class AuditLogResource {

    @Inject
    DataStore store;

    @Inject
    CurrentUser currentUser;

    /**
     * 安全(静默过滤型):无论传入谁的 userId,都只返回调用者自己的日志。
     * 用来检验检测平台能否区分"返回了自己的数据/空数据"与"真越权"。
     */
    @GET
    public List<Models.AuditLog> list(@QueryParam("userId") String userId) {
        return store.auditLogsOfUser(currentUser.get().id());
    }
}
