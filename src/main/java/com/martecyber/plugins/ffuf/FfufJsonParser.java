package com.martecyber.plugins.ffuf;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.martecyber.ares.assets.AssetType;
import com.martecyber.ares.imports.ImportParser;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.imports.ParsedAsset;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Parses ffuf JSON output ({@code ffuf -of json}).
 *
 * Creates web_endpoint assets for every discovered URL and derives a parent
 * web_application from the common origin (scheme + host + port).
 * No detections are emitted — ffuf is an enumeration tool only.
 */
@Component
public class FfufJsonParser implements ImportParser {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override public String getToolId()    { return "ffuf"; }
    @Override public String getDisplayName() { return "ffuf JSON"; }
    @Override public String[] getSupportedExtensions() { return new String[]{".json"}; }

    @Override
    public boolean validate(byte[] content) {
        String s = new String(content, StandardCharsets.UTF_8).trim();
        // ffuf JSON: top-level object with a "results" array whose entries have "url" + "status"
        return s.startsWith("{") && s.contains("\"results\"") && s.contains("\"status\"")
            && s.contains("\"url\"") && !s.contains("\"target_url\""); // exclude wpscan
    }

    @Override
    public ParseResult parse(byte[] content) throws Exception {
        ParseResult result = new ParseResult();
        JsonNode root = MAPPER.readTree(content);

        JsonNode resultsNode = root.get("results");
        if (resultsNode == null || !resultsNode.isArray() || resultsNode.isEmpty()) {
            result.addWarning("No results found in ffuf output");
            return result;
        }

        Set<String> seenEndpoints = new HashSet<>();
        Set<String> seenApps     = new HashSet<>();

        for (JsonNode r : resultsNode) {
            String url = text(r, "url");
            if (url == null || url.isBlank()) continue;
            // Strip query string: endpoint identifier is path-only
            url = stripQuery(url);
            if (!seenEndpoints.add(url)) continue;

            // Derive and register the parent web_application (scheme + host + port)
            String appId = baseApp(url);
            if (appId != null && seenApps.add(appId)) {
                result.addAsset(new ParsedAsset(appId, AssetType.WEB_APPLICATION, Map.of()));
            }

            Map<String, Object> meta = new LinkedHashMap<>();
            if (r.has("status"))       meta.put("statusCodes",  new ArrayList<>(List.of(r.get("status").asInt())));
            if (r.has("length"))       meta.put("lengths",      new ArrayList<>(List.of(r.get("length").asLong())));
            if (r.has("words"))        meta.put("wordCounts",   new ArrayList<>(List.of(r.get("words").asLong())));
            if (r.has("content-type")) meta.put("contentTypes", new ArrayList<>(List.of(r.get("content-type").asText())));
            String redir = r.path("redirectlocation").asText("");
            if (!redir.isBlank()) meta.put("redirectLocations", new ArrayList<>(List.of(redir)));

            result.addAsset(new ParsedAsset(url, AssetType.WEB_ENDPOINT, meta));
        }

        return result;
    }

    private static String stripQuery(String url) {
        try {
            URI uri = new URI(url.trim());
            String path = uri.getRawPath() != null ? uri.getRawPath() : "";
            String base = uri.getScheme() + "://" + uri.getHost()
                + (uri.getPort() == -1 ? "" : ":" + uri.getPort());
            return path.isEmpty() || path.equals("/") ? base : base + path;
        } catch (Exception e) {
            return url;
        }
    }

    private static String baseApp(String url) {
        try {
            URI uri = new URI(url);
            String scheme = uri.getScheme();
            String host   = uri.getHost();
            if (scheme == null || host == null) return null;
            int port = uri.getPort();
            boolean defaultPort = ("https".equals(scheme) && port == 443)
                || ("http".equals(scheme) && port == 80) || port == -1;
            return scheme + "://" + host + (defaultPort ? "" : ":" + port);
        } catch (Exception e) {
            return null;
        }
    }

    private static String text(JsonNode node, String field) {
        JsonNode n = node.get(field);
        return (n != null && !n.isNull() && n.isTextual() && !n.asText().isBlank()) ? n.asText() : null;
    }
}
