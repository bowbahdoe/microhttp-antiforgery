package dev.mccue.microhttp.antiforgery;

import dev.mccue.microhttp.handler.IntoResponse;
import dev.mccue.microhttp.session.Session;
import dev.mccue.microhttp.session.SessionManager;
import org.microhttp.Request;
import org.microhttp.Response;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;

import static dev.mccue.microhttp.antiforgery.ScopedSessionStrategy.checkEqual;
import static dev.mccue.microhttp.antiforgery.ScopedSessionStrategy.sessionToken;
final class SessionStrategy implements AntiForgeryStrategy {
    final SessionManager sessionManager;

    SessionStrategy(SessionManager sessionManager) {
        this.sessionManager = sessionManager;
    }

    @Override
    public boolean validToken(Request request, String token) {
        var sessionData = sessionManager
                .read(request)
                .map(Session::data)
                .orElse(null);
        if (sessionData == null) {
            return false;
        }

        var sessionToken = sessionToken(sessionData);
        if (sessionToken != null) {
            return checkEqual(token, sessionToken);
        }

        return false;
    }

    @Override
    public String getToken(Request request) {
        var sessionData = sessionManager
                .read(request)
                .map(Session::data)
                .orElse(null);

        if (sessionData != null) {
            var sessionToken = sessionToken(sessionData);
            if (sessionToken != null) {
                return sessionToken;
            }
        }


        byte[] bytes = new byte[60];
        new SecureRandom().nextBytes(bytes);

        return Base64.getEncoder().encodeToString(bytes);
    }

    @Override
    public IntoResponse writeToken(Request request, IntoResponse response, String token) {
        var actualResponse = response.intoResponse();

        var session = sessionManager
                .read(actualResponse)
                .orElse(new Session());

        var sessionData = session.data();

        String oldToken = null;
        if (sessionData != null) {
            oldToken = sessionToken(sessionData);
        }

        if (!checkEqual(token, oldToken)) {
            var headers = new ArrayList<>(actualResponse.headers());
            headers.add(sessionManager.write(session.update(data -> data.with("__anti_forgery_token", token))));
            return () -> new Response(
                    actualResponse.status(),
                    actualResponse.reason(),
                    Collections.unmodifiableList(headers),
                    actualResponse.body()
            );
        }
        return response;
    }
}
