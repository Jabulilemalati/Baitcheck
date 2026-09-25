package com.baitcheck.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

public final class Headers {

    private final Map<String, List<String>> values = new LinkedHashMap<>();

    public void add(String name, String value) {
        values.computeIfAbsent(key(name), k -> new ArrayList<>()).add(value);
    }

    public Optional<String> first(String name) {
        List<String> list = values.get(key(name));
        return (list == null || list.isEmpty()) ? Optional.empty() : Optional.of(list.get(0));
    }

    public List<String> all(String name) {
        return Collections.unmodifiableList(values.getOrDefault(key(name), List.of()));
    }

    public boolean has(String name) {
        return values.containsKey(key(name));
    }

    private static String key(String name) {
        return name.trim().toLowerCase(Locale.ROOT);
    }
}
