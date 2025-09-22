package com.toprankdigitalsolutions.security.sonarqube;

import lombok.Data;

import java.util.stream.Collectors;
import java.util.stream.Stream;

@Data
public class Hotspot {
    private String key;
    private String component;
    private String project;
    private String securityCategory;
    private String vulnerabilityProbability;
    private String status;
    private String line;
    private String message;
    private String author;
    private String creationDate;
    private String updateDate;

    public String toCsvRow() {
        return Stream.of(
            key,
            component,
            project,
            securityCategory,
            vulnerabilityProbability,
            status,
            line,
            message,
            author,
            creationDate,
            updateDate
        )
        .map(value -> value.replaceAll("\"", "\"\""))
        .map(value -> Stream.of("\"", ",").anyMatch(value::contains) ? "\"" + value + "\"" : value)
        .collect(Collectors.joining(","));
    }
}
