package com.baitcheck.analysis;

import com.baitcheck.analyzers.AttachmentAnalyzer;
import com.baitcheck.analyzers.AuthenticationAnalyzer;
import com.baitcheck.analyzers.ContentAnalyzer;
import com.baitcheck.analyzers.HeaderAnalyzer;
import com.baitcheck.analyzers.LinkAnalyzer;
import com.baitcheck.model.Email;

import java.util.ArrayList;
import java.util.List;

public final class PhishAnalyzer {

    private final List<Analyzer> analyzers;

    public PhishAnalyzer() {
        this(List.of(
                new HeaderAnalyzer(),
                new AuthenticationAnalyzer(),
                new LinkAnalyzer(),
                new ContentAnalyzer(),
                new AttachmentAnalyzer()));
    }

    public PhishAnalyzer(List<Analyzer> analyzers) {
        this.analyzers = List.copyOf(analyzers);
    }

    public AnalysisResult analyze(Email email) {
        List<Finding> findings = new ArrayList<>();
        for (Analyzer analyzer : analyzers) {
            findings.addAll(analyzer.analyze(email));
        }
        return AnalysisResult.of(email, findings);
    }
}
