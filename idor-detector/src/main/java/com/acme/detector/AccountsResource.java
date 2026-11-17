package com.acme.detector;

import com.acme.detector.Models.Account;
import jakarta.inject.Inject;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.Collection;
import java.util.Map;

@Path("/api/accounts")
@Produces(MediaType.APPLICATION_JSON)
public class AccountsResource {

    @Inject
    DetectorState state;

    @GET
    public Collection<Account> list() {
        return state.accounts.values();
    }

    /** 新增/更新账号。body: {name, baseUrl, headers:{...}, note} */
    @POST
    public Response upsert(Account account) {
        if (account == null || account.name() == null || account.name().isBlank()
                || account.baseUrl() == null || account.baseUrl().isBlank()) {
            return Response.status(400).entity(Map.of("error", "name 和 baseUrl 必填")).build();
        }
        state.accounts.put(account.name(), account);
        return Response.ok(account).build();
    }

    @DELETE
    @Path("/{name}")
    public Response delete(@PathParam("name") String name) {
        return state.accounts.remove(name) != null
                ? Response.noContent().build()
                : Response.status(404).build();
    }
}
