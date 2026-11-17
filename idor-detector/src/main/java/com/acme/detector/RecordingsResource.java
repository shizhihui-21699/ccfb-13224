package com.acme.detector;

import com.acme.detector.Models.RecordedRequest;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.inject.Inject;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * 请求录制:高权限账号抓到的业务请求推到这里。
 * 支持逐条 POST,也支持导入浏览器/抓包工具导出的 HAR 文件。
 */
@Path("/api/recordings")
@Produces(MediaType.APPLICATION_JSON)
public class RecordingsResource {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** 认证类请求头不保存 —— 重放时会换成各测试账号的凭证。 */
    private static final List<String> SKIP_HEADERS = List.of(
            "authorization", "cookie", "x-token", "content-length", "host", "connection");

    @Inject
    DetectorState state;

    @GET
    public List<RecordedRequest> list() {
        return state.recordings;
    }

    /** 录一条请求。body: {method, path, headers?, body?, note?} */
    @POST
    public RecordedRequest add(RecordedRequest req) {
        RecordedRequest saved = new RecordedRequest(
                req.id() != null ? req.id() : UUID.randomUUID().toString().substring(0, 8),
                req.method().toUpperCase(),
                req.path(),
                req.headers() == null ? Map.of() : req.headers(),
                req.body(),
                req.note(),
                Instant.now());
        state.recordings.add(saved);
        return saved;
    }

    /** 导入 HAR(只取 method/url/headers/postData,自动去掉认证头)。 */
    @POST
    @Path("/har")
    public Response importHar(String harJson) {
        int imported = 0;
        try {
            JsonNode entries = MAPPER.readTree(harJson).path("log").path("entries");
            for (JsonNode entry : entries) {
                JsonNode req = entry.path("request");
                String method = req.path("method").asText("GET");
                URI uri = URI.create(req.path("url").asText());
                String path = uri.getRawPath() + (uri.getRawQuery() != null ? "?" + uri.getRawQuery() : "");
                Map<String, String> headers = new java.util.HashMap<>();
                req.path("headers").forEach(h -> {
                    String name = h.path("name").asText().toLowerCase();
                    if (!SKIP_HEADERS.contains(name) && !name.startsWith(":")) {
                        headers.put(h.path("name").asText(), h.path("value").asText());
                    }
                });
                String body = req.path("postData").path("text").asText(null);
                add(new RecordedRequest(null, method, path, headers, body, "HAR 导入", null));
                imported++;
            }
        } catch (Exception e) {
            return Response.status(400).entity(Map.of("error", "HAR 解析失败: " + e.getMessage())).build();
        }
        return Response.ok(Map.of("imported", imported)).build();
    }

    @DELETE
    @Path("/{id}")
    public Response delete(@PathParam("id") String id) {
        boolean removed = state.recordings.removeIf(r -> r.id().equals(id));
        return removed ? Response.noContent().build() : Response.status(404).build();
    }

    @DELETE
    public Response clear() {
        state.recordings.clear();
        return Response.noContent().build();
    }
}
