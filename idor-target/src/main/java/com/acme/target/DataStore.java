package com.acme.target;

import com.acme.target.Models.AuditLog;
import com.acme.target.Models.Document;
import com.acme.target.Models.Invoice;
import com.acme.target.Models.Order;
import com.acme.target.Models.User;
import jakarta.annotation.PostConstruct;
import jakarta.inject.Singleton;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * 内存数据仓库。预置两个租户的数据:
 *  - tenant-a: admin-a(高权限) / user-a(低权限)
 *  - tenant-b: user-b(另一租户)
 *
 * 注意用 @Singleton 而不是 @ApplicationScoped:后者是正常作用域,
 * 注入的是客户端代理,直接访问字段拿不到真实例的数据。
 */
@Singleton
public class DataStore {

    public final Map<String, User> usersByToken = new LinkedHashMap<>();
    public final Map<String, User> usersById = new LinkedHashMap<>();
    public final Map<String, Order> orders = new LinkedHashMap<>();
    public final Map<String, Invoice> invoices = new LinkedHashMap<>();
    public final Map<String, Document> documents = new LinkedHashMap<>();
    public final Map<String, AuditLog> auditLogs = new LinkedHashMap<>();

    @PostConstruct
    void seed() {
        // ---- 用户 ----
        addUser(new User("u-admin-a", "tenant-a", "张管理", "admin@tenant-a.example", "13800000001", "ADMIN"),
                "token-admin-a");
        addUser(new User("u-user-a", "tenant-a", "李普通", "user@tenant-a.example", "13800000002", "USER"),
                "token-user-a");
        addUser(new User("u-user-b", "tenant-b", "王隔壁", "user@tenant-b.example", "13900000003", "USER"),
                "token-user-b");

        // ---- 订单 ----
        orders.put("o-1001", new Order("o-1001", "tenant-a", "u-user-a", "机械键盘", 2, "CREATED"));
        orders.put("o-1002", new Order("o-1002", "tenant-a", "u-admin-a", "显示器", 1, "PAID"));
        orders.put("o-1003", new Order("o-1003", "tenant-a", "u-user-a", "鼠标", 5, "SHIPPED"));
        orders.put("o-2001", new Order("o-2001", "tenant-b", "u-user-b", "人体工学椅", 1, "CREATED"));
        orders.put("o-2002", new Order("o-2002", "tenant-b", "u-user-b", "升降桌", 1, "PAID"));

        // ---- 发票 ----
        invoices.put("inv-5001", new Invoice("inv-5001", "tenant-a", "u-user-a", 598.0, "INV-A-0001"));
        invoices.put("inv-5002", new Invoice("inv-5002", "tenant-a", "u-admin-a", 2499.0, "INV-A-0002"));
        invoices.put("inv-6001", new Invoice("inv-6001", "tenant-b", "u-user-b", 1899.0, "INV-B-0001"));

        // ---- 文档 ----
        documents.put("d-9001", new Document("d-9001", "tenant-a", "u-user-a", "A公司报销制度", "报销需部门主管审批……"));
        documents.put("d-9002", new Document("d-9002", "tenant-a", "u-admin-a", "A公司薪资结构(机密)", "P7  base 45k……"));
        documents.put("d-9501", new Document("d-9501", "tenant-b", "u-user-b", "B公司团建方案", "周五下午轰趴……"));

        // ---- 审计日志(按用户归属) ----
        auditLogs.put("log-1", new AuditLog("log-1", "u-user-a", "LOGIN", "李普通 登录系统"));
        auditLogs.put("log-2", new AuditLog("log-2", "u-admin-a", "EXPORT", "张管理 导出订单"));
        auditLogs.put("log-3", new AuditLog("log-3", "u-user-b", "LOGIN", "王隔壁 登录系统"));
    }

    private void addUser(User u, String token) {
        usersById.put(u.id(), u);
        usersByToken.put(token, u);
    }

    public Optional<User> authenticate(String token) {
        if (token == null) return Optional.empty();
        return Optional.ofNullable(usersByToken.get(token));
    }

    public List<Order> ordersOfTenant(String tenantId) {
        return orders.values().stream().filter(o -> o.tenantId().equals(tenantId)).toList();
    }

    public List<Invoice> invoicesOfOwner(String ownerId) {
        return invoices.values().stream().filter(i -> i.ownerId().equals(ownerId)).toList();
    }

    public List<Invoice> invoicesOfTenant(String tenantId) {
        return invoices.values().stream().filter(i -> i.tenantId().equals(tenantId)).toList();
    }

    public List<Document> documentsOfTenant(String tenantId) {
        return documents.values().stream().filter(d -> d.tenantId().equals(tenantId)).toList();
    }

    public List<AuditLog> auditLogsOfUser(String userId) {
        return auditLogs.values().stream().filter(l -> l.userId().equals(userId)).toList();
    }
}
