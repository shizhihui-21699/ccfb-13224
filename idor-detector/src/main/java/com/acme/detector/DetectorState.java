package com.acme.detector;

import com.acme.detector.Models.Account;
import com.acme.detector.Models.Finding;
import com.acme.detector.Models.RecordedRequest;
import com.acme.detector.Models.ScanResult;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/** 平台状态:账号、录制的请求、历次扫描结果。内存存储,重启即清空。 */
@ApplicationScoped
public class DetectorState {

    public final Map<String, Account> accounts = new ConcurrentHashMap<>();
    public final List<RecordedRequest> recordings = new CopyOnWriteArrayList<>();
    public final Map<String, ScanResult> scans = new ConcurrentHashMap<>();
    public volatile String latestScanId;

    public Optional<ScanResult> latestScan() {
        String id = latestScanId;
        return id == null ? Optional.empty() : Optional.ofNullable(scans.get(id));
    }

    public void addScan(ScanResult scan) {
        scans.put(scan.id(), scan);
        latestScanId = scan.id();
    }

    public List<Finding> latestFindings() {
        return latestScan().map(ScanResult::findings).orElse(List.of());
    }
}
