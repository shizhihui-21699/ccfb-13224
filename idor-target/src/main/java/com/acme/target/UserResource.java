package com.acme.target;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

@Path("/api")
@Produces(MediaType.APPLICATION_JSON)
public class UserResource {

    @Inject
    DataStore store;

    @Inject
    CurrentUser currentUser;

    /** 安全:返回自己的资料。 */
    @GET
    @Path("/profile")
    public Models.User profile() {
        return currentUser.get();
    }

    /**
     * 【越权点 #4】按 ID 查用户资料(含手机号、邮箱等 PII)未做归属校验,
     * 可遍历任意租户用户。
     */
    @GET
    @Path("/users/{id}")
    public Response getUser(@PathParam("id") String id) {
        Models.User user = store.usersById.get(id);
        if (user == null) {
            return Response.status(404).entity(Models.error("NOT_FOUND", "用户不存在")).build();
        }
        // BUG: 未校验目标用户是否与当前用户同租户/有查看权限
        return Response.ok(user).build();
    }
}
