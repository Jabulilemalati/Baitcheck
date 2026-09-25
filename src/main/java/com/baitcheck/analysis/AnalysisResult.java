package com.baitcheck.analysis;

import com.baitcheck.model.Email;

import java.util.Comparator;
import java.util.List;

public record AnalysisResult(Email email, List<Finding> findings, int score, Verdict verdict) {

    public static AnalysisResult of(Email email, List<Finding> findings) {
        int total = findings.stream().mapToInt(f -> f.severity().points()).sum();
        int score = Math.min(100, total);
        List<Finding> sorted = findings.stream()
                .sorted(Comparator.comparing(Finding::severity).reversed())
                .toList();
        return new AnalysisResult(email, sorted, score, Verdict.forScore(score));
    }

    public long count(Severity severity) {
        return findings.stream().filter(f -> f.severity() == severity).count();
    }
}
