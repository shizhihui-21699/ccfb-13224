package com.acme.target;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.List;

@Path("/api/orders")
@Produces(MediaType.APPLICATION_JSON)
public class OrderResource {

    @Inject
    DataStore store;

    @Inject
    CurrentUser currentUser;

    /** 安全:只列本租户订单。 */
    @GET
    public List<Models.Order> list() {
        return store.ordersOfTenant(currentUser.get().tenantId());
    }

    /**
     * 【越权点 #1】按 ID 查订单时没有做租户/归属校验 —— 经典 IDOR。
     * 任何登录用户都能读到任意租户的订单。
     */
    @GET
    @Path("/{id}")
    public Response get(@PathParam("id") String id) {
        Models.Order order = store.orders.get(id);
        if (order == null) {
            return Response.status(404).entity(Models.error("NOT_FOUND", "订单不存在")).build();
        }
        // BUG: 缺少 order.tenantId().equals(currentUser.get().tenantId()) 校验
        return Response.ok(order).build();
    }

    /**
     * 【越权点 #2】修改订单状态同样没有归属校验 —— 写操作 IDOR。
     */
    @PUT
    @Path("/{id}/status")
    public Response updateStatus(@PathParam("id") String id, @QueryParam("status") String status) {
        Models.Order order = store.orders.get(id);
        if (order == null) {
            return Response.status(404).entity(Models.error("NOT_FOUND", "订单不存在")).build();
        }
        // BUG: 写操作前未校验订单归属
        Models.Order updated = order.withStatus(status == null ? "UNKNOWN" : status);
        store.orders.put(id, updated);
        return Response.ok(updated).build();
    }
}
