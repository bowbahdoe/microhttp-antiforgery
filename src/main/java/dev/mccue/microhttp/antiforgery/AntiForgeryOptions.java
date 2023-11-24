package dev.mccue.microhttp.antiforgery;

import dev.mccue.microhttp.handler.Handler;
import dev.mccue.microhttp.handler.IntoResponse;
import dev.mccue.microhttp.html.HtmlResponse;
import org.microhttp.Request;

import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;

import static dev.mccue.html.Html.HTML;

public final class AntiForgeryOptions {
    final Handler errorHandler;
    final AntiForgeryStrategy strategy;
    final Function<Request, Optional<String>> readToken;

    AntiForgeryOptions(Builder builder) {
        this.errorHandler = builder.errorHandler;
        this.strategy = builder.strategy;
        this.readToken = builder.readToken;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        Handler errorHandler;
        AntiForgeryStrategy strategy;
        Function<Request, Optional<String>> readToken;

        Builder() {
            this.errorHandler = __ -> new HtmlResponse(
                    403,
                    HTML."<h1>Invalid anti-forgery token</h1>"
            );
            this.strategy = AntiForgeryStrategy.scopedSession();
            this.readToken = AntiForgery::requestToken;
        }

        public Builder errorHandler(Handler handler) {
            this.errorHandler = Objects.requireNonNull(handler);
            return this;
        }

        public Builder errorResponse(IntoResponse intoResponse) {
            Objects.requireNonNull(intoResponse);
            this.errorHandler = __ -> intoResponse;
            return this;
        }

        public Builder strategy(AntiForgeryStrategy strategy) {
            this.strategy = Objects.requireNonNull(strategy);
            return this;
        }

        public Builder readToken(Function<Request, Optional<String>> readToken) {
            this.readToken = Objects.requireNonNull(readToken);
            return this;
        }

        public AntiForgeryOptions build() {
            return new AntiForgeryOptions(this);
        }
    }
}
