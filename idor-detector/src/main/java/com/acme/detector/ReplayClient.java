package com.acme.detector;

import com.acme.detector.Models.Account;
import com.acme.detector.Models.ReplayResult;
import jakarta.enterprise.context.ApplicationScoped;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;

/** 用 JDK HttpClient 以指定账号身份重放请求。 */
@ApplicationScoped
public class ReplayClient {

    private final HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

    public ReplayResult replay(Account account, String method, String path, String body) {
        try {
            String url = account.baseUrl().replaceAll("/+$", "") + path;
            HttpRequest.Builder b = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(10));
            // 账号凭证头
            account.headers().forEach(b::header);
            // 请求体
            String m = method.toUpperCase();
            HttpRequest.BodyPublisher publisher = (body == null || body.isEmpty())
                    ? HttpRequest.BodyPublishers.noBody()
                    : HttpRequest.BodyPublishers.ofString(body);
            if (body != null && !body.isEmpty()) {
                b.header("Content-Type", "application/json");
            }
            b.method(m, publisher);
            HttpResponse<String> resp = client.send(b.build(), HttpResponse.BodyHandlers.ofString());
            return new ReplayResult(resp.statusCode(), resp.body() == null ? "" : resp.body(), null);
        } catch (Exception e) {
            return new ReplayResult(-1, "", e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }
}
