package com.acme.target;

import jakarta.annotation.Priority;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import java.io.IOException;

/** 简单令牌认证:请求头 X-Token -> 用户。未认证一律 401。 */
@Provider
@Singleton
@Priority(Priorities.AUTHENTICATION)
public class AuthFilter implements ContainerRequestFilter {

    @Inject
    DataStore store;

    @Inject
    CurrentUser currentUser;

    @Override
    public void filter(ContainerRequestContext ctx) throws IOException {
        String path = ctx.getUriInfo().getPath();
        if (path != null && path.startsWith("/")) {
            path = path.substring(1);
        }
        if (path == null || !path.startsWith("api/")) {
            return;
        }
        String token = ctx.getHeaderString("X-Token");
        var user = store.authenticate(token);
        if (user.isEmpty()) {
            ctx.abortWith(Response.status(Response.Status.UNAUTHORIZED)
                    .entity(Models.error("UNAUTHORIZED", "缺少或无效的 X-Token"))
                    .build());
            return;
        }
        currentUser.set(user.get());
    }
}
