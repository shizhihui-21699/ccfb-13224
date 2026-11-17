package com.acme.target;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.List;

@Path("/api/documents")
@Produces(MediaType.APPLICATION_JSON)
public class DocumentResource {

    @Inject
    DataStore store;

    @Inject
    CurrentUser currentUser;

    /** 安全:只列本租户文档。 */
    @GET
    public List<Models.Document> list() {
        return store.documentsOfTenant(currentUser.get().tenantId());
    }

    /** 安全:跨租户访问返回 404(不暴露存在性)。 */
    @GET
    @Path("/{id}")
    public Response get(@PathParam("id") String id) {
        Models.Document doc = store.documents.get(id);
        if (doc == null || !doc.tenantId().equals(currentUser.get().tenantId())) {
            return Response.status(404).entity(Models.error("NOT_FOUND", "文档不存在")).build();
        }
        return Response.ok(doc).build();
    }
}
