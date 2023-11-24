package dev.mccue.microhttp.antiforgery;

import dev.mccue.microhttp.handler.IntoResponse;
import dev.mccue.microhttp.session.SessionManager;
import org.microhttp.Request;

public interface AntiForgeryStrategy {
    boolean validToken(Request request, String token);

    String getToken(Request request);

    IntoResponse writeToken(Request request, IntoResponse response, String token);

    static AntiForgeryStrategy scopedSession() {
        return new ScopedSessionStrategy();
    }


    static AntiForgeryStrategy session(SessionManager sessionManager) {
        return new SessionStrategy(sessionManager);
    }
}
