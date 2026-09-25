package com.baitcheck.report;

import com.baitcheck.analysis.AnalysisResult;
import com.baitcheck.analysis.Finding;
import com.baitcheck.analysis.Severity;
import com.baitcheck.analysis.Verdict;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

import static com.baitcheck.util.HtmlUtils.escape;

public final class HtmlReport {

    public void write(List<AnalysisResult> results, Path target) throws IOException {
        StringBuilder html = new StringBuilder();
        html.append("""
                <!DOCTYPE html>
                <html lang="en"><head><meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>BaitCheck report</title>
                <style>
                  body{font-family:system-ui,Segoe UI,Roboto,sans-serif;background:#f4f5f7;color:#1d2330;margin:0;padding:24px}
                  h1{margin:0 0 4px} .muted{color:#667085;font-size:14px}
                  .card{background:#fff;border-radius:10px;padding:18px 20px;margin:18px 0;box-shadow:0 1px 3px rgba(0,0,0,.08)}
                  .head{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}
                  .verdict{font-weight:700;padding:6px 12px;border-radius:999px;color:#fff}
                  .LIKELY_PHISHING{background:#c0392b} .SUSPICIOUS{background:#d68910} .LIKELY_SAFE{background:#1e8449}
                  .bar{height:8px;background:#e4e7ec;border-radius:4px;margin:10px 0 14px;overflow:hidden}
                  .bar span{display:block;height:100%}
                  table{width:100%;border-collapse:collapse;font-size:14px}
                  td{padding:7px 6px;border-top:1px solid #eef0f3;vertical-align:top}
                  .sev{font-weight:700;font-size:12px;white-space:nowrap}
                  .HIGH{color:#c0392b} .MEDIUM{color:#b9770e} .LOW{color:#2471a3} .INFO{color:#8a94a6}
                  .detail{color:#475467;word-break:break-word}
                </style></head><body>
                <h1>BaitCheck report</h1>
                """);
        html.append("<div class=\"muted\">Generated ")
                .append(LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")))
                .append(" &middot; ").append(results.size()).append(" email(s) analysed</div>\n");

        for (AnalysisResult r : results) {
            Verdict v = r.verdict();
            html.append("<div class=\"card\"><div class=\"head\"><div><strong>")
                    .append(escape(r.email().source())).append("</strong><div class=\"muted\">From: ")
                    .append(escape(r.email().from().toString())).append("<br>Subject: ")
                    .append(escape(r.email().subject())).append("</div></div>")
                    .append("<span class=\"verdict ").append(v.name()).append("\">")
                    .append(escape(v.label())).append(" &middot; ").append(r.score()).append("/100</span></div>\n");
            html.append("<div class=\"bar\"><span class=\"").append(v.name()).append("\" style=\"width:")
                    .append(r.score()).append("%\"></span></div>\n<table>\n");
            for (Finding f : r.findings()) {
                html.append("<tr><td class=\"sev ").append(f.severity().name()).append("\">")
                        .append(f.severity()).append("</td><td>").append(escape(f.category()))
                        .append("</td><td><strong>").append(escape(f.title()))
                        .append("</strong><div class=\"detail\">").append(escape(f.detail()))
                        .append("</div></td></tr>\n");
            }
            if (r.findings().stream().noneMatch(f -> f.severity() != Severity.INFO)) {
                html.append("<tr><td colspan=\"3\">No warning signs found.</td></tr>\n");
            }
            html.append("</table></div>\n");
        }
        html.append("</body></html>\n");
        Files.writeString(target, html.toString(), StandardCharsets.UTF_8);
    }
}
