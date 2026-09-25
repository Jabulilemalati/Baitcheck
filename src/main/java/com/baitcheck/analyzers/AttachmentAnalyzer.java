package com.baitcheck.analyzers;

import com.baitcheck.analysis.Analyzer;
import com.baitcheck.analysis.Finding;
import com.baitcheck.model.Attachment;
import com.baitcheck.model.Email;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public final class AttachmentAnalyzer implements Analyzer {

    private static final String CAT = "Attachments";

    private static final Set<String> EXECUTABLE = Set.of(
            "exe", "scr", "com", "pif", "bat", "cmd", "js", "jse", "vbs", "vbe", "wsf", "ps1",
            "jar", "msi", "hta", "lnk", "iso", "img", "vhd", "cpl", "dll", "apk");
    private static final Set<String> MACRO_OFFICE = Set.of("docm", "xlsm", "pptm", "dotm", "xlam");
    private static final Set<String> HTML = Set.of("html", "htm", "shtml", "svg");
    private static final Set<String> ARCHIVE = Set.of("zip", "rar", "7z", "gz", "tar", "cab");
    private static final Set<String> DOCUMENT_LIKE = Set.of(
            "pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt", "csv");

    @Override
    public List<Finding> analyze(Email email) {
        List<Finding> out = new ArrayList<>();
        for (Attachment a : email.attachments()) {
            String name = a.filename().toLowerCase(Locale.ROOT).trim();
            String[] parts = name.split("\\.");
            String ext = parts.length > 1 ? parts[parts.length - 1] : "";
            String label = a.filename() + " (" + a.contentType() + ", " + a.sizeBytes() + " bytes)";

            if (parts.length > 2 && DOCUMENT_LIKE.contains(parts[parts.length - 2])
                    && !DOCUMENT_LIKE.contains(ext)) {
                out.add(Finding.high(CAT, "Double file extension",
                        label + " - Windows hides the last extension, so this looks like a ."
                                + parts[parts.length - 2] + " but is really a ." + ext));
            }
            if (EXECUTABLE.contains(ext)) {
                out.add(Finding.high(CAT, "Executable or script attachment", label));
            } else if (MACRO_OFFICE.contains(ext)) {
                out.add(Finding.high(CAT, "Macro-enabled Office document",
                        label + " - macros are one of the most common malware delivery methods"));
            } else if (HTML.contains(ext)) {
                out.add(Finding.medium(CAT, "HTML attachment",
                        label + " - often a fake login page that opens locally to dodge URL filters"));
            } else if (ARCHIVE.contains(ext)) {
                out.add(Finding.low(CAT, "Compressed archive",
                        label + " - archives can hide malicious files from email scanners"));
            } else {
                out.add(Finding.info(CAT, "Attachment", label));
            }
        }
        return out;
    }
}
