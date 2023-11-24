package dev.mccue.microhttp.antiforgery;

import dev.mccue.json.JsonDecoder;
import dev.mccue.microhttp.handler.IntoResponse;
import dev.mccue.microhttp.session.ScopedSession;
import dev.mccue.microhttp.session.SessionData;
import org.microhttp.Request;

import java.security.SecureRandom;
import java.util.Base64;

final class ScopedSessionStrategy implements AntiForgeryStrategy {
    static String sessionToken(SessionData sessionData) {
        return sessionData.get(AntiForgery.TOKEN_NAME, JsonDecoder::string)
                .orElse(null);
    }

    // Timing resistant equality check
    static boolean checkEqual(String a, String b) {
        if (a != null && b != null && a.length() == b.length()) {
            int total = 0;
            for (int i = 0; i < a.length(); i++) {
                total |= a.charAt(i) ^ b.charAt(i);
            }
            return total == 0;
        }
        return false;
    }

    @Override
    public boolean validToken(Request request, String token) {
        var sessionToken = sessionToken(ScopedSession.get());
        if (sessionToken != null) {
            return checkEqual(token, sessionToken);
        }

        return false;
    }

    @Override
    public String getToken(Request request) {
        var sessionToken = sessionToken(ScopedSession.get());
        if (sessionToken != null) {
            return sessionToken;
        }

        byte[] bytes = new byte[60];
        new SecureRandom().nextBytes(bytes);

        return Base64.getEncoder().encodeToString(bytes);
    }

    @Override
    public IntoResponse writeToken(Request request, IntoResponse response, String token) {
        var oldToken = sessionToken(ScopedSession.get());
        if (!checkEqual(token, oldToken)) {
            ScopedSession.update(data -> data.with(AntiForgery.TOKEN_NAME, token));
        }
        return response;
    }
}
