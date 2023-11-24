module dev.mccue.microhttp.antiforgery {
    requires dev.mccue.microhttp.session;
    requires dev.mccue.urlparameters;

    requires transitive dev.mccue.microhttp.html;
    requires transitive dev.mccue.microhttp.handler;

    exports dev.mccue.microhttp.antiforgery;
}