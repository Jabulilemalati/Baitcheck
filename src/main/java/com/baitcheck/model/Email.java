package com.baitcheck.model;

import com.baitcheck.util.HtmlUtils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public final class Email {

    private final String source;
    private final Headers headers;
    private final StringBuilder textBody = new StringBuilder();
    private final StringBuilder htmlBody = new StringBuilder();
    private final List<Attachment> attachments = new ArrayList<>();

    public Email(String source, Headers headers) {
        this.source = source;
        this.headers = headers;
    }

    public String source() {
        return source;
    }

    public Headers headers() {
        return headers;
    }

    public EmailAddress from() {
        return EmailAddress.parse(headers.first("From").orElse(null));
    }

    public String subject() {
        return headers.first("Subject").orElse("(no subject)");
    }

    public String textBody() {
        return textBody.toString();
    }

    public String htmlBody() {
        return htmlBody.toString();
    }

    public List<Attachment> attachments() {
        return Collections.unmodifiableList(attachments);
    }

    public void appendText(String text) {
        textBody.append(text).append('\n');
    }

    public void appendHtml(String html) {
        htmlBody.append(html).append('\n');
    }

    public void addAttachment(Attachment attachment) {
        attachments.add(attachment);
    }

    public String readableText() {
        return subject() + "\n" + textBody + "\n" + HtmlUtils.stripTags(htmlBody.toString());
    }
}
