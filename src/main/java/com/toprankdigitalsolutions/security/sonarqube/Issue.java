package com.toprankdigitalsolutions.security.sonarqube;

import lombok.Data;

import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * For the POC it's missing "flows" and "tags". These two are array attributes.
 */
@Data
public class Issue {
    private String key;
    private String rule;
    private String severity;
    private String component;
    private String project;
    private String line;
    private String hash;
    private String textRange_startLine;
    private String textRange_endLine;
    private String textRange_startOffset;
    private String textRange_endOffset;
    private String status;
    private String message;
    private String effort;
    private String debt;
    private String author;
    private String creationDate;
    private String updateDate;
    private String type;
    private String scope;

    public String toCsvRow() {
        return Stream.of(
                        key,
                        rule,
                        severity,
                        component,
                        project,
                        line,
                        hash,
                        textRange_startLine,
                        textRange_endLine,
                        textRange_startOffset,
                        textRange_endOffset,
                        status,
                        message,
                        effort,
                        debt,
                        author,
                        creationDate,
                        updateDate,
                        type,
                        scope)
                .map(value -> value.replaceAll("\"", "\"\""))
                .map(value -> Stream.of("\"", ",").anyMatch(value::contains) ? "\"" + value + "\"" : value)
                .collect(Collectors.joining(","));
    }
}
