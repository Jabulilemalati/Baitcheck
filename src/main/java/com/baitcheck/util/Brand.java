package com.baitcheck.util;

import java.util.List;

public record Brand(String name, List<String> keywords, List<String> domains) {

    public static final List<Brand> CATALOG = List.of(
            new Brand("PayPal", List.of("paypal"), List.of("paypal.com")),
            new Brand("Microsoft", List.of("microsoft", "office 365", "microsoft 365", "onedrive", "outlook"),
                    List.of("microsoft.com", "office.com", "live.com", "outlook.com",
                            "microsoftonline.com", "sharepoint.com")),
            new Brand("Apple", List.of("apple", "icloud"), List.of("apple.com", "icloud.com")),
            new Brand("Google", List.of("google", "gmail"), List.of("google.com", "gmail.com", "youtube.com")),
            new Brand("Amazon", List.of("amazon"), List.of("amazon.com", "amazon.co.za")),
            new Brand("Netflix", List.of("netflix"), List.of("netflix.com")),
            new Brand("DHL", List.of("dhl"), List.of("dhl.com", "dhl.co.za")),
            new Brand("SARS", List.of("sars", "efiling"), List.of("sars.gov.za")),
            new Brand("Absa", List.of("absa"), List.of("absa.co.za", "absa.africa")),
            new Brand("FNB", List.of("fnb", "first national bank"), List.of("fnb.co.za")),
            new Brand("Standard Bank", List.of("standard bank", "standardbank"), List.of("standardbank.co.za")),
            new Brand("Capitec", List.of("capitec"), List.of("capitecbank.co.za")),
            new Brand("Nedbank", List.of("nedbank"), List.of("nedbank.co.za")),
            new Brand("Takealot", List.of("takealot"), List.of("takealot.com"))
    );

    public boolean owns(String host) {
        String registrable = DomainUtils.registrableDomain(host);
        return domains.stream().anyMatch(d -> d.equals(registrable));
    }
}
