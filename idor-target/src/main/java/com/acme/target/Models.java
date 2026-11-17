package com.acme.target;

import java.util.List;

/** 靶场领域模型。 */
public final class Models {

    public record User(String id, String tenantId, String name, String email, String phone, String role) {}

    public record Order(String id, String tenantId, String ownerId, String item, int amount, String status) {
        public Order withStatus(String newStatus) {
            return new Order(id, tenantId, ownerId, item, amount, newStatus);
        }
    }

    public record Invoice(String id, String tenantId, String ownerId, double total, String number) {}

    public record Document(String id, String tenantId, String ownerId, String title, String content) {}

    public record AuditLog(String id, String userId, String action, String detail) {}

    public record ErrorBody(String error, String message) {}

    public static ErrorBody error(String code, String message) {
        return new ErrorBody(code, message);
    }

    private Models() {}
}
