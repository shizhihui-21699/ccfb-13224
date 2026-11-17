package com.acme.target;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.List;

@Path("/api/invoices")
@Produces(MediaType.APPLICATION_JSON)
public class InvoiceResource {

    @Inject
    DataStore store;

    @Inject
    CurrentUser currentUser;

    /**
     * 【越权点 #3】ownerId 由客户端传入且未校验是否本人/本租户,
     * 可遍历任意用户(含其他租户)的发票。不传 ownerId 时是安全的。
     */
    @GET
    public List<Models.Invoice> list(@QueryParam("ownerId") String ownerId) {
        if (ownerId != null && !ownerId.isBlank()) {
            // BUG: 未校验 ownerId 是否属于当前用户
            return store.invoicesOfOwner(ownerId);
        }
        return store.invoicesOfTenant(currentUser.get().tenantId());
    }

    /** 安全:跨租户返回 404。 */
    @GET
    @Path("/{id}")
    public Response get(@PathParam("id") String id) {
        Models.Invoice invoice = store.invoices.get(id);
        if (invoice == null || !invoice.tenantId().equals(currentUser.get().tenantId())) {
            return Response.status(404).entity(Models.error("NOT_FOUND", "发票不存在")).build();
        }
        return Response.ok(invoice).build();
    }

    /**
     * 安全(静默空数据型):跨租户不报错,直接返回空数组。
     * 用来检验检测平台能否把"返回空数据"与"真越权"区分开。
     */
    @GET
    @Path("/{id}/payments")
    public List<String> payments(@PathParam("id") String id) {
        Models.Invoice invoice = store.invoices.get(id);
        if (invoice == null || !invoice.tenantId().equals(currentUser.get().tenantId())) {
            return List.of();
        }
        return List.of("pmt-" + id + "-1");
    }
}
