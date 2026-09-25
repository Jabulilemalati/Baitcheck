package com.baitcheck.parser;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

public record ContentType(String value, Map<String, String> params) {

    public static ContentType parse(String header) {
        Map<String, String> params = new LinkedHashMap<>();
        if (header == null || header.isBlank()) {
            return new ContentType("", params);
        }
        String[] parts = splitOnSemicolons(header);
        String value = parts[0].trim().toLowerCase(Locale.ROOT);
        for (int i = 1; i < parts.length; i++) {
            String p = parts[i].trim();
            int eq = p.indexOf('=');
            if (eq <= 0) {
                continue;
            }
            String key = p.substring(0, eq).trim().toLowerCase(Locale.ROOT);
            String val = p.substring(eq + 1).trim();
            if (val.length() >= 2 && val.startsWith("\"") && val.endsWith("\"")) {
                val = val.substring(1, val.length() - 1);
            }
            params.put(key, val);
        }
        return new ContentType(value, params);
    }

    public String param(String name) {
        return params.get(name.toLowerCase(Locale.ROOT));
    }

    private static String[] splitOnSemicolons(String s) {
        java.util.List<String> out = new java.util.ArrayList<>();
        StringBuilder cur = new StringBuilder();
        boolean inQuotes = false;
        for (char c : s.toCharArray()) {
            if (c == '"') {
                inQuotes = !inQuotes;
            }
            if (c == ';' && !inQuotes) {
                out.add(cur.toString());
                cur.setLength(0);
            } else {
                cur.append(c);
            }
        }
        out.add(cur.toString());
        return out.toArray(new String[0]);
    }
}
