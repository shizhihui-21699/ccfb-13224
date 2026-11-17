package com.acme.detector;

import com.acme.detector.Models.EndpointReport;
import com.acme.detector.Models.Finding;
import com.acme.detector.Models.ScanConfig;
import com.acme.detector.Models.ScanResult;
import com.acme.detector.Models.Verdict;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Path("/api")
@Produces(MediaType.APPLICATION_JSON)
public class ScanResource {

    @Inject
    DetectorState state;

    @Inject
    ScanService scanService;

    /** 发起扫描。body: {baselineAccount, lowPrivAccount, crossTenantAccount, similarityThreshold?} */
    @POST
    @Path("/scan")
    public Response scan(ScanConfig cfg) {
        if (state.recordings.isEmpty()) {
            return Response.status(400).entity(Map.of("error", "还没有录制任何请求")).build();
        }
        try {
            ScanResult result = scanService.runScan(cfg);
            return Response.ok(result).build();
        } catch (IllegalArgumentException e) {
            return Response.status(400).entity(Map.of("error", e.getMessage())).build();
        }
    }

    @GET
    @Path("/scans")
    public List<Map<String, Object>> scans() {
        return state.scans.values().stream()
                .sorted(Comparator.comparing(ScanResult::startedAt).reversed())
                .map(s -> {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("id", s.id());
                    m.put("startedAt", s.startedAt().toString());
                    m.put("findings", s.findings().size());
                    m.put("vulnerable", s.findings().stream().filter(f -> f.verdict() == Verdict.VULNERABLE).count());
                    return m;
                })
                .toList();
    }

    @GET
    @Path("/scans/{id}")
    public Response scanDetail(@PathParam("id") String id) {
        ScanResult s = state.scans.get(id);
        return s == null ? Response.status(404).build() : Response.ok(s).build();
    }

    /** 最近一次扫描按接口归组的报告。 */
    @GET
    @Path("/report/latest")
    public Response latestReport() {
        return state.latestScan()
                .map(s -> Response.ok(groupByEndpoint(s.findings())).build())
                .orElse(Response.status(404).entity(Map.of("error", "还没有扫描结果")).build());
    }

    static List<EndpointReport> groupByEndpoint(List<Finding> findings) {
        Map<String, List<Finding>> grouped = new LinkedHashMap<>();
        findings.forEach(f -> grouped.computeIfAbsent(f.endpointKey(), k -> new ArrayList<>()).add(f));
        List<EndpointReport> reports = new ArrayList<>();
        grouped.forEach((key, list) -> {
            long vuln = list.stream().filter(f -> f.verdict() == Verdict.VULNERABLE).count();
            long susp = list.stream().filter(f -> f.verdict() == Verdict.SUSPICIOUS).count();
            long err = list.stream().filter(f -> f.verdict() == Verdict.ERROR).count();
            long safe = list.size() - vuln - susp - err;
            Verdict worst = vuln > 0 ? Verdict.VULNERABLE
                    : susp > 0 ? Verdict.SUSPICIOUS
                    : err > 0 && safe == 0 ? Verdict.ERROR
                    : Verdict.SAFE_DENIED;
            reports.add(new EndpointReport(key, worst, vuln, susp, safe, err, list));
        });
        // 越权的排最前
        reports.sort(Comparator.comparing(EndpointReport::worstVerdict));
        return reports;
    }
}
