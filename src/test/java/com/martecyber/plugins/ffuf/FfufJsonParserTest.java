package com.martecyber.plugins.ffuf;

import com.martecyber.ares.assets.AssetType;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.imports.ParsedAsset;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/** Covers {@link FfufJsonParser}: query-string stripping on the endpoint identifier, the derived
 *  parent web_application (with default-port suppression), and that no detections are ever
 *  emitted — ffuf is enumeration-only. */
class FfufJsonParserTest {

    private final FfufJsonParser parser = new FfufJsonParser();

    private ParseResult parse(String json) throws Exception {
        return parser.parse(json.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void validateRequiresResultsStatusAndUrlButRejectsWpscanShape() {
        String ok = "{\"results\":[{\"url\":\"http://a\",\"status\":200}]}";
        assertTrue(parser.validate(ok.getBytes(StandardCharsets.UTF_8)));
        // wpscan JSON also has a "url" field but is keyed by "target_url" — must be excluded.
        String wpscan = "{\"target_url\":\"http://a\",\"results\":[{\"url\":\"http://a\",\"status\":200}]}";
        assertFalse(parser.validate(wpscan.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void emptyResultsArrayProducesAWarningAndNoAssets() throws Exception {
        ParseResult result = parse("{\"results\":[]}");
        assertTrue(result.getAssets().isEmpty());
        assertFalse(result.getWarnings().isEmpty());
    }

    @Test
    void endpointIdentifierStripsTheQueryStringButKeepsThePath() throws Exception {
        ParseResult result = parse("""
            {"results":[{"url":"http://example.com/admin?debug=1","status":200,"length":123,"words":10,"content-type":"text/html"}]}
            """);

        ParsedAsset endpoint = result.getAssets().stream()
            .filter(a -> a.getType().equals(AssetType.WEB_ENDPOINT)).findFirst().orElseThrow();
        assertEquals("http://example.com/admin", endpoint.getIdentifier());
        assertEquals(java.util.List.of(200), endpoint.getMetadata().get("statusCodes"));
        assertEquals(java.util.List.of(123L), endpoint.getMetadata().get("lengths"));
        assertEquals(java.util.List.of("text/html"), endpoint.getMetadata().get("contentTypes"));
    }

    @Test
    void derivesParentWebApplicationSuppressingTheDefaultPort() throws Exception {
        ParseResult result = parse("""
            {"results":[
              {"url":"https://example.com:443/a","status":200},
              {"url":"https://example.com:8443/b","status":200}
            ]}
            """);

        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals(AssetType.WEB_APPLICATION) && a.getIdentifier().equals("https://example.com")));
        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals(AssetType.WEB_APPLICATION) && a.getIdentifier().equals("https://example.com:8443")));
    }

    @Test
    void duplicateUrlsAfterQueryStrippingAreOnlyEmittedOnce() throws Exception {
        ParseResult result = parse("""
            {"results":[
              {"url":"http://example.com/admin?x=1","status":200},
              {"url":"http://example.com/admin?x=2","status":301}
            ]}
            """);
        assertEquals(1, result.getAssets().stream().filter(a -> a.getType().equals(AssetType.WEB_ENDPOINT)).count());
    }

    @Test
    void noDetectionsAreEverEmitted() throws Exception {
        ParseResult result = parse("{\"results\":[{\"url\":\"http://example.com/a\",\"status\":200}]}");
        assertTrue(result.getDetections().isEmpty());
    }

    @Test
    void entriesWithoutAUrlAreSkipped() throws Exception {
        ParseResult result = parse("{\"results\":[{\"status\":200},{\"url\":\"http://example.com/a\",\"status\":200}]}");
        assertEquals(1, result.getAssets().stream().filter(a -> a.getType().equals(AssetType.WEB_ENDPOINT)).count());
    }
}
