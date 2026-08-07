/*
 * Integration test for the custom "Condition - ACR value (exact LoA match)" SPI.
 *
 * Boots a real Keycloak 26.4 container with this provider mounted and the actual
 * poc realm imported (../realm/poc-realm.json), then drives full authorization-code
 * + PKCE logins over HTTP and asserts the resulting acr / amr claims. This proves
 * the exact-match routing end-to-end:
 *   - client `postman` (exact):  acr/low -> password only (acr=low, amr=pwd)
 *                                default  -> passkey subflow (acr=high, amr=pwd via fallback)
 *   - client `postman-cumulative` (built-in): acr/low -> password (acr=low)
 *
 * Passkey ceremonies can't run headlessly, so the tests exercise the password
 * paths; the acr values still prove which subflow each ACR selected.
 */
package it.westlund.kc.acr;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.util.stream.Collectors.joining;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AcrExactConditionIT {

    private static final String REALM = "poc";
    private static final String REDIRECT = "https://oauth.pstmn.io/v1/callback";
    private static final String ACR_LOW = "http://example.com/loa/low";
    private static final String ACR_HIGH = "http://example.com/loa/high";
    private static final String ACR_X509 = "http://example.com/loa/x509";

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Pattern FORM_ACTION = Pattern.compile("action=\"([^\"]+)\"");
    private static final Pattern TITLE = Pattern.compile("<title>(.*?)</title>", Pattern.DOTALL);

    private static KeycloakContainer keycloak;

    @BeforeAll
    static void startKeycloak() {
        keycloak = new KeycloakContainer(System.getProperty("keycloak.image", "quay.io/keycloak/keycloak:26.4"))
                .withProviderClassesFrom("target/classes")   // mounts the freshly compiled SPI
                .withRealmImportFile("poc-realm.json");       // the real ../realm/poc-realm.json
        keycloak.start();
    }

    @AfterAll
    static void stopKeycloak() {
        if (keycloak != null) {
            keycloak.stop();
        }
    }

    // --- the assertions ----------------------------------------------------

    @Test
    void exactClient_low_usesPasswordOnly() throws Exception {
        JsonNode idToken = login("postman", ACR_LOW);
        assertEquals(ACR_LOW, idToken.get("acr").asText(), "low path must resolve to the low ACR");
        assertTrue(amr(idToken).contains("pwd"), "low path must be password (amr=pwd)");
    }

    @Test
    void exactClient_default_isX509_notPasswordOrPasskey() throws Exception {
        // The client's default.acr.values is loa/x509, so a request with no acr_values
        // routes to the X.509 subflow. Headless over plain HTTP there is no client
        // certificate, so it cannot complete AND must not fall back to a password /
        // passkey / username form.
        Outcome o = run(new Http(keycloak.getAuthServerUrl()), b64url(random(40)), "postman", null);
        assertNull(o.code(), "default (X.509) cannot complete without a client certificate");
        String p = o.terminalPage().toLowerCase();
        assertFalse(p.contains("name=\"password\""), "default path must go to X.509, not a password form");
        assertFalse(p.contains("name=\"username\""), "default path must go to X.509, not a username form");
    }

    @Test
    void exactClient_high_isIdentityFirst_noPasswordOnFirstPage() throws Exception {
        // The passkey path is now requested explicitly with loa/high. It is
        // identity-first: the FIRST page asks for a username only, never a password.
        String page = authorizePage("postman", ACR_HIGH).toLowerCase();
        assertTrue(page.contains("name=\"username\""), "passkey path must start by asking for a username");
        assertFalse(page.contains("name=\"password\""), "the first (identify) page must have no password field");
    }

    @Test
    void exactClient_high_passkeylessUser_verifiesPasswordThenEnrols() throws Exception {
        // alice has no passkey: username -> password verify -> land on the passkey
        // REGISTRATION page (create a passkey). No token headlessly.
        Outcome o = run(new Http(keycloak.getAuthServerUrl()), b64url(random(40)), "postman", ACR_HIGH);
        assertNull(o.code(), "a passkey-less user cannot complete the passkey path headlessly");
        String p = o.terminalPage().toLowerCase();
        assertTrue(p.contains("attestationobject") || p.contains("register"),
                "passkey-less user must be sent to passkey registration");
    }

    @Test
    void exactClient_high_thenLow_hasNoPasskeyNag() throws Exception {
        // Running the passkey path (which triggers the enrolment step) must NOT
        // leave a persistent required action: a subsequent low/password login must
        // still return a token, not the passkey-registration page.
        run(new Http(keycloak.getAuthServerUrl()), b64url(random(40)), "postman", ACR_HIGH);
        JsonNode idToken = login("postman", ACR_LOW);
        assertEquals(ACR_LOW, idToken.get("acr").asText(),
                "password path must still complete after the passkey path ran");
        assertTrue(amr(idToken).contains("pwd"));
    }

    @Test
    void exactClient_multipleAcrValues_usesHighest() throws Exception {
        // acr_values is a space-separated list; the custom SPI selects the HIGHEST requested level.
        // "low high" -> max is high (passkey), so the identity-first username page appears -- NOT the
        // password form that Keycloak's built-in .min() collapse (low) would have produced.
        String page = authorizePage("postman", ACR_LOW + " " + ACR_HIGH).toLowerCase();
        assertTrue(page.contains("name=\"username\""),
                "highest (passkey) path must start with a username prompt");
        assertFalse(page.contains("name=\"password\""),
                "must not be the low/password form (the .min() collapse would have shown it)");
    }

    @Test
    void cumulativeClient_low_usesPasswordOnly() throws Exception {
        JsonNode idToken = login("postman-cumulative", ACR_LOW);
        assertEquals(ACR_LOW, idToken.get("acr").asText());
        assertTrue(amr(idToken).contains("pwd"));
    }

    // --- HTTP auth-code + PKCE driver -------------------------------------

    /** Result of driving a login: either an authorization code, or the terminal page HTML. */
    private record Outcome(String code, String terminalPage) { }

    private String authorizeUrl(String base, String clientId, String acrValues, String challenge) {
        StringBuilder auth = new StringBuilder(base)
                .append("/realms/").append(REALM).append("/protocol/openid-connect/auth")
                .append("?client_id=").append(enc(clientId))
                .append("&response_type=code&scope=openid&state=xyz")
                .append("&redirect_uri=").append(enc(REDIRECT))
                .append("&code_challenge=").append(challenge)
                .append("&code_challenge_method=S256");
        if (acrValues != null) {
            auth.append("&acr_values=").append(enc(acrValues));
        }
        return auth.toString();
    }

    /** Just fetch the first login page for the given client/ACR (no login submitted). */
    private String authorizePage(String clientId, String acrValues) throws Exception {
        String base = keycloak.getAuthServerUrl();
        String challenge = b64url(sha256(b64url(random(40))));
        HttpResponse<String> page = new Http(base).followGet(authorizeUrl(base, clientId, acrValues, challenge));
        assertEquals(200, page.statusCode(), "authorize should render a login page");
        return page.body();
    }

    /**
     * Drive whatever credential forms appear (username, then password, ...) as alice,
     * until we reach an authorization code or a page with no username/password form
     * (a passkey login / passkey registration page).
     */
    private Outcome run(Http http, String verifier, String clientId, String acrValues) throws Exception {
        String base = http.base;
        String page = http.followGet(authorizeUrl(base, clientId, acrValues, b64url(sha256(verifier)))).body();
        for (int step = 0; step < 6; step++) {
            Matcher am = FORM_ACTION.matcher(page);
            boolean hasForm = am.find();
            boolean hasUser = page.contains("name=\"username\"");
            boolean hasPass = page.contains("name=\"password\"");
            if (!hasForm || (!hasUser && !hasPass)) {
                return new Outcome(null, page);   // terminal: passkey / register / webauthn page
            }
            StringBuilder body = new StringBuilder("credentialId=");
            if (hasUser) body.append("&username=alice");
            if (hasPass) body.append("&password=alice");
            String[] adv = advance(http, http.post(unescape(am.group(1)), body.toString()));
            if ("code".equals(adv[0])) {
                return new Outcome(adv[1], null);
            }
            page = adv[1];
        }
        throw new AssertionError("Too many login steps without reaching a code or terminal page");
    }

    private JsonNode login(String clientId, String acrValues) throws Exception {
        String base = keycloak.getAuthServerUrl();
        String verifier = b64url(random(40));
        Http http = new Http(base);
        Outcome o = run(http, verifier, clientId, acrValues);
        assertNotNull(o.code(), () -> "expected a token but landed on '"
                + find(TITLE, o.terminalPage(), "?") + "' (needs a real authenticator)");

        String tokenBody = "grant_type=authorization_code&code=" + o.code()
                + "&redirect_uri=" + enc(REDIRECT)
                + "&client_id=" + enc(clientId)
                + "&code_verifier=" + verifier;
        HttpResponse<String> tok = http.post(
                base + "/realms/" + REALM + "/protocol/openid-connect/token", tokenBody);
        assertEquals(200, tok.statusCode(), "token exchange failed: " + tok.body());
        return decodeJwt(MAPPER.readTree(tok.body()).get("id_token").asText());
    }

    /** Follow a post-submit response: return {"code",code} at the callback, else {"page",html}. */
    private String[] advance(Http http, HttpResponse<String> resp) throws Exception {
        int guard = 0;
        while (resp.statusCode() / 100 == 3 && guard++ < 10) {
            String loc = resp.headers().firstValue("location").orElseThrow();
            if (loc.startsWith(REDIRECT)) {
                return new String[]{"code", queryParam(loc, "code")};
            }
            resp = http.get(loc.startsWith("http") ? loc : http.base + loc);
        }
        return new String[]{"page", resp.body()};
    }

    // --- tiny cookie-aware HTTP client (ignores Secure so it works over http) ---

    private static final class Http {
        final HttpClient client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER).build();
        final Map<String, String> cookies = new LinkedHashMap<>();
        final String base;

        Http(String base) { this.base = base; }

        HttpResponse<String> get(String url) throws Exception {
            HttpResponse<String> r = client.send(HttpRequest.newBuilder(URI.create(url))
                    .header("Cookie", cookieHeader()).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            store(r);
            return r;
        }

        HttpResponse<String> post(String url, String body) throws Exception {
            HttpResponse<String> r = client.send(HttpRequest.newBuilder(URI.create(url))
                    .header("Cookie", cookieHeader())
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(body)).build(),
                    HttpResponse.BodyHandlers.ofString());
            store(r);
            return r;
        }

        HttpResponse<String> followGet(String url) throws Exception {
            HttpResponse<String> r = get(url);
            int guard = 0;
            while (r.statusCode() / 100 == 3 && guard++ < 10) {
                String loc = r.headers().firstValue("location").orElseThrow();
                r = get(loc.startsWith("http") ? loc : base + loc);
            }
            return r;
        }

        private void store(HttpResponse<?> r) {
            for (String sc : r.headers().allValues("set-cookie")) {
                String first = sc.split(";", 2)[0];
                int eq = first.indexOf('=');
                if (eq > 0) {
                    cookies.put(first.substring(0, eq).trim(), first.substring(eq + 1).trim());
                }
            }
        }

        private String cookieHeader() {
            return cookies.entrySet().stream()
                    .map(e -> e.getKey() + "=" + e.getValue()).collect(joining("; "));
        }
    }

    // --- helpers -----------------------------------------------------------

    private static List<String> amr(JsonNode idToken) {
        List<String> out = new ArrayList<>();
        JsonNode a = idToken.get("amr");
        if (a != null && a.isArray()) {
            a.forEach(n -> out.add(n.asText()));
        }
        return out;
    }

    private static JsonNode decodeJwt(String jwt) throws Exception {
        String payload = jwt.split("\\.")[1];
        byte[] json = Base64.getUrlDecoder().decode(payload);
        return MAPPER.readTree(json);
    }

    private static String find(Pattern p, String s, String dflt) {
        Matcher m = p.matcher(s);
        return m.find() ? m.group(1) : dflt;
    }

    private static String unescape(String s) {
        return s.replace("&amp;", "&");
    }

    private static String queryParam(String url, String key) {
        for (String kv : url.substring(url.indexOf('?') + 1).split("&")) {
            String[] p = kv.split("=", 2);
            if (p[0].equals(key)) {
                return p[1];
            }
        }
        throw new AssertionError("no '" + key + "' in " + url);
    }

    private static String enc(String s) {
        return java.net.URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    private static byte[] random(int n) {
        byte[] b = new byte[n];
        new SecureRandom().nextBytes(b);
        return b;
    }

    private static byte[] sha256(String s) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.US_ASCII));
    }

    private static String b64url(byte[] b) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }
}
