package dev.mccue.microhttp.antiforgery;

import dev.mccue.html.Html;
import dev.mccue.microhttp.handler.Handler;
import dev.mccue.urlparameters.UrlParameters;
import org.microhttp.Request;

import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.function.Function;

import static dev.mccue.html.Html.HTML;

public final class AntiForgery {
    static final String TOKEN_NAME = "__anti_forgery_token";
    private AntiForgery() {}

    static Optional<String> requestToken(Request request) {
        var contentType = request.header("content-type");
        if (contentType != null && contentType.startsWith("application/x-www-form-urlencoded")) {
            var formBody = UrlParameters.parse(new String(request.body(), StandardCharsets.UTF_8))
                    .firstValue(TOKEN_NAME)
                    .orElse(null);
            if (formBody != null) {
                return Optional.of(formBody);
            }
        }

        var csrfToken = request.header("x-csrf-token");
        if (csrfToken != null) {
            return Optional.of(csrfToken);
        }

        var xsrfToken = request.header("x-xsrf-token");
        if (xsrfToken != null) {
            return Optional.of(xsrfToken);
        }

        return Optional.empty();
    }

    static boolean isGetLike(Request request) {
        return request.method().equalsIgnoreCase("get") ||
               request.method().equalsIgnoreCase("head") ||
               request.method().equalsIgnoreCase("options");
    }

    static boolean validRequest(
            AntiForgeryStrategy strategy,
            Request request,
            Function<Request, Optional<String>> readToken
    ) {
        if (isGetLike(request)) {
            return true;
        }

        var token = readToken.apply(request).orElse(null);
        if (token != null) {
            return strategy.validToken(request, token);
        }

        return false;
    }

    public static Handler wrap(Handler handler) {
        return wrap(handler, AntiForgeryOptions.builder().build());
    }
    public static Handler wrap(Handler handler, AntiForgeryOptions options) {
        return request -> {
            if (validRequest(options.strategy, request, options.readToken)) {
                var token = options.strategy.getToken(request);
                return ScopedValue.where(ANTI_FORGERY_TOKEN, token)
                        .call(() -> {
                            var intoResponse = handler.handle(request);
                            var response = intoResponse.intoResponse();
                            return options.strategy.writeToken(request, () -> response, token);
                        });
            }
            else {
                return options.errorHandler.handle(request);
            }
        };
    }

    public static final ScopedValue<String> ANTI_FORGERY_TOKEN
            = ScopedValue.newInstance();

    public static String token() {
        return ANTI_FORGERY_TOKEN.get();
    }

    public static Html field() {
        return HTML."<input type=\"hidden\" name=\"\{TOKEN_NAME}\" id=\"\{TOKEN_NAME}\" value=\"\{token()}\"></input>";
    }
}
