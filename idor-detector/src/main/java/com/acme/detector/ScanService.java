package com.acme.detector;

import com.acme.detector.Models.Account;
import com.acme.detector.Models.Finding;
import com.acme.detector.Models.RecordedRequest;
import com.acme.detector.Models.ReplayResult;
import com.acme.detector.Models.ScanConfig;
import com.acme.detector.Models.ScanResult;
import com.acme.detector.Models.TestType;
import com.acme.detector.Models.Verdict;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * 扫描流程:
 *  1. 用三个账号分别重放所有 GET 请求,收集各自"可见的对象编号/标识"作为归属池;
 *  2. 每条录制请求:高权限基线 → 低权限重放 → 跨租户重放;
 *  3. 把请求里的对象编号替换成"别的账号池里的编号"再重放(IDOR 探测);
 *  4. 逐条判定:拒绝 / 空数据 / 自己的数据 / 拿到别人的数据。
 */
@ApplicationScoped
public class ScanService {

    /** 相似度 ≥ 阈值 => 视为"拿到了与基线实质相同的数据"。 */
    public static final double DEFAULT_THRESHOLD = 0.8;
    /** 0.5 ~ 阈值之间 => 疑似,人工复核。 */
    public static final double SUSPICIOUS_FLOOR = 0.5;

    @Inject
    DetectorState state;

    @Inject
    ReplayClient client;

    @Inject
    ComparatorService comparator;

    public ScanResult runScan(ScanConfig cfg) {
        Account baseline = mustAccount(cfg.baselineAccount());
        Account lowPriv = mustAccount(cfg.lowPrivAccount());
        Account crossTenant = mustAccount(cfg.crossTenantAccount());
        double threshold = cfg.similarityThreshold() > 0 ? cfg.similarityThreshold() : DEFAULT_THRESHOLD;

        List<Finding> findings = new ArrayList<>();
        Instant started = Instant.now();

        // ---- 第 1 步:归属池 ----
        // 全量池:各账号重放所有 GET 后可见的标识(可能被越权端点污染,仅用于"认识"所有对象编号);
        // 自身池:只从"请求里不含对象编号"的 GET(列表/自查接口)收集,代表该账号天然可见的数据,
        //        不会被"按 ID 越权读"污染。
        List<Account> accounts = List.of(baseline, lowPriv, crossTenant);
        Map<String, Set<String>> fullPools = harvestPools(accounts, rec -> true);
        Set<String> knownIds = new LinkedHashSet<>();
        fullPools.values().forEach(knownIds::addAll);
        Map<String, Set<String>> selfPools = harvestPools(accounts,
                rec -> IdToolkit.extractFromRequest(rec.path(), rec.body(), knownIds).isEmpty());

        // ---- 第 2、3 步:逐条录制请求做三种测试 ----
        for (RecordedRequest rec : state.recordings) {
            ReplayResult base = client.replay(baseline, rec.method(), rec.path(), rec.body());
            String baseNorm = comparator.normalize(base.body());

            for (Account attacker : List.of(lowPriv, crossTenant)) {
                TestType directType = attacker.name().equals(lowPriv.name())
                        ? TestType.VERTICAL_REPLAY : TestType.CROSS_TENANT_REPLAY;

                // 受害方标记 = 其他账号全量池里有、而该账号自身池里没有的标识
                Set<String> victimMarkers = victimMarkers(fullPools, selfPools, attacker.name());
                Set<String> ownMarkers = selfPools.getOrDefault(attacker.name(), Set.of());

                // (a) 原样重放
                evaluate(findings, rec, rec.path(), rec.body(), attacker, directType,
                        base, baseNorm, null, victimMarkers, ownMarkers, knownIds, threshold);

                // (b) ID 替换:把请求中的对象编号换成受害方的
                for (String reqId : IdToolkit.extractFromRequest(rec.path(), rec.body(), knownIds)) {
                    String victimId = pickVictimId(reqId, victimMarkers);
                    if (victimId == null) continue;
                    String newPath = IdToolkit.replace(rec.path(), reqId, victimId);
                    String newBody = IdToolkit.replace(rec.body(), reqId, victimId);
                    // 替换后的基线:高权限账号访问受害对象,得到"该对象真实数据"
                    ReplayResult subBase = client.replay(baseline, rec.method(), newPath, newBody);
                    String subBaseNorm = comparator.normalize(subBase.body());
                    evaluate(findings, rec, newPath, newBody, attacker, TestType.ID_SUBSTITUTION,
                            subBase, subBaseNorm, victimId, victimMarkers, ownMarkers, knownIds, threshold);
                }
            }
        }

        ScanResult result = new ScanResult(UUID.randomUUID().toString().substring(0, 8),
                new ScanConfig(baseline.name(), lowPriv.name(), crossTenant.name(), threshold),
                started, Instant.now(), List.copyOf(findings));
        state.addScan(result);
        return result;
    }

    private void evaluate(List<Finding> findings, RecordedRequest rec, String path, String body,
                          Account attacker, TestType type,
                          ReplayResult base, String baseNorm,
                          String substitutedId, Set<String> victimMarkers, Set<String> ownMarkers,
                          Set<String> knownIds, double threshold) {
        ReplayResult r = client.replay(attacker, rec.method(), path, body);

        Verdict verdict;
        String evidence;
        double similarity = 0.0;

        if (!r.ok()) {
            verdict = Verdict.ERROR;
            evidence = "重放失败: " + r.error();
        } else if (r.status() == 401 || r.status() == 403) {
            verdict = Verdict.SAFE_DENIED;
            evidence = "服务器拒绝访问(HTTP " + r.status() + ")";
        } else if (r.status() == 404) {
            verdict = Verdict.SAFE_DENIED;
            evidence = "对象对该账号不可见(HTTP 404)";
        } else if (r.status() >= 500) {
            verdict = Verdict.ERROR;
            evidence = "服务器错误(HTTP " + r.status() + "),无法判定";
        } else if (r.status() >= 200 && r.status() < 300) {
            if (comparator.isEmptyData(r.body())) {
                verdict = Verdict.SAFE_EMPTY;
                evidence = "返回空数据,未泄露任何对象";
            } else {
                String replayNorm = comparator.normalize(r.body());
                similarity = comparator.similarity(baseNorm, replayNorm);
                List<String> hits = new ArrayList<>(comparator.matchedMarkers(r.body(), victimMarkers));
                if (substitutedId != null && r.body() != null && r.body().contains(substitutedId)) {
                    hits.add(0, substitutedId);
                }
                if (!hits.isEmpty()) {
                    verdict = Verdict.VULNERABLE;
                    evidence = "响应中包含受害方标识 " + abbrev(hits)
                            + (substitutedId != null ? "(请求中的对象编号被替换成了受害方的,仍返回了数据)" : "");
                } else if (similarity >= threshold) {
                    // 响应里的标识是否全部落在该账号自己本来就可见的范围内
                    Set<String> responseMarkers = IdToolkit.harvestMarkers(r.body());
                    boolean allOwn = !responseMarkers.isEmpty() && ownMarkers.containsAll(responseMarkers);
                    if (allOwn) {
                        verdict = Verdict.SAFE_DIFFERENT;
                        evidence = String.format("相似度 %.0f%%,但返回数据均在该账号自身可见范围内,未越权",
                                similarity * 100);
                    } else if (type == TestType.VERTICAL_REPLAY) {
                        // 低权限账号拿到与高权限一致、且无法归因的响应:垂直越权嫌疑,交人工确认权限矩阵
                        verdict = Verdict.SUSPICIOUS;
                        evidence = String.format("低权限账号响应与高权限基线相似度 %.0f%% ≥ 阈值 %.0f%%,"
                                + "需人工确认该接口是否应对低权限开放", similarity * 100, threshold * 100);
                    } else {
                        verdict = Verdict.VULNERABLE;
                        evidence = String.format("响应与高权限基线相似度 %.0f%% ≥ 阈值 %.0f%%,拿到了实质相同的数据",
                                similarity * 100, threshold * 100);
                    }
                } else if (similarity >= SUSPICIOUS_FLOOR) {
                    verdict = Verdict.SUSPICIOUS;
                    evidence = String.format("响应与基线相似度 %.0f%%,介于 %.0f%%~%.0f%% 之间,需人工复核",
                            similarity * 100, SUSPICIOUS_FLOOR * 100, threshold * 100);
                } else {
                    verdict = Verdict.SAFE_DIFFERENT;
                    evidence = String.format("返回内容相似度仅 %.0f%%,为调用者自身数据,未泄露他人数据", similarity * 100);
                }
            }
        } else {
            verdict = Verdict.ERROR;
            evidence = "未预期的状态码 HTTP " + r.status();
        }

        findings.add(new Finding(
                UUID.randomUUID().toString().substring(0, 8),
                endpointKey(rec.method(), path, knownIds),
                type,
                attacker.name(),
                rec.id(),
                path,
                substitutedId,
                r.status(),
                base.status(),
                Math.round(similarity * 1000) / 1000.0,
                verdict,
                evidence,
                snippet(base.body()),
                snippet(r.body())));
    }

    /** 归组键:METHOD + 路径模板(对象编号段换成 {id},去掉 query)。 */
    static String endpointKey(String method, String path, Set<String> knownIds) {
        String p = path.split("\\?")[0];
        StringBuilder sb = new StringBuilder();
        for (String seg : p.split("/")) {
            if (seg.isEmpty()) continue;
            boolean isId = seg.matches("([A-Za-z]+-)?\\d{3,}")
                    || seg.matches("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-.*")
                    || knownIds.contains(seg);
            sb.append('/').append(isId ? "{id}" : seg);
        }
        return method.toUpperCase() + " " + sb;
    }

    /** 让每个账号重放所有(满足条件的)GET 录制请求,收集响应里出现的标识。 */
    private Map<String, Set<String>> harvestPools(List<Account> accounts,
                                                  java.util.function.Predicate<RecordedRequest> filter) {
        Map<String, Set<String>> pools = new java.util.HashMap<>();
        for (Account acc : accounts) {
            Set<String> pool = new LinkedHashSet<>();
            for (RecordedRequest rec : state.recordings) {
                if (!"GET".equalsIgnoreCase(rec.method()) || !filter.test(rec)) continue;
                ReplayResult r = client.replay(acc, rec.method(), rec.path(), rec.body());
                if (r.ok() && r.status() >= 200 && r.status() < 300) {
                    pool.addAll(IdToolkit.harvestMarkers(r.body()));
                }
            }
            pools.put(acc.name(), pool);
        }
        return pools;
    }

    private Set<String> victimMarkers(Map<String, Set<String>> fullPools,
                                      Map<String, Set<String>> selfPools, String attackerName) {
        Set<String> own = selfPools.getOrDefault(attackerName, Set.of());
        Set<String> victims = new LinkedHashSet<>();
        fullPools.forEach((name, pool) -> {
            if (!name.equals(attackerName)) {
                pool.stream().filter(m -> !own.contains(m)).forEach(victims::add);
            }
        });
        return victims;
    }

    /** 为请求中的 ID 挑选替换值:只接受同前缀(同类型)的受害方编号,没有就放弃本次替换。 */
    private String pickVictimId(String requestId, Set<String> victimMarkers) {
        String prefix = IdToolkit.prefixOf(requestId);
        for (String m : victimMarkers) {
            if (!m.equals(requestId) && IdToolkit.prefixOf(m).equals(prefix)) {
                return m;
            }
        }
        return null;
    }

    private Account mustAccount(String name) {
        Account acc = state.accounts.get(name);
        if (acc == null) {
            throw new IllegalArgumentException("账号不存在: " + name);
        }
        return acc;
    }

    private static String abbrev(List<String> items) {
        return items.size() <= 3 ? items.toString()
                : items.subList(0, 3) + " 等 " + items.size() + " 个";
    }

    private static String snippet(String body) {
        if (body == null) return "";
        String t = body.replaceAll("\\s+", " ").trim();
        return t.length() > 300 ? t.substring(0, 300) + "…" : t;
    }
}
