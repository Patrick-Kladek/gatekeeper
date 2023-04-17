import Vapor

/// Middleware used to rate-limit a single route or a group of routes.
public struct GatekeeperMiddleware: Middleware {
    private let config: GatekeeperConfig?
    private let keyMaker: GatekeeperKeyMaker?
    private let error: Error?
    
    /// Initialize a new middleware for rate-limiting routes, by optionally overriding default configurations.
    ///
    /// - Parameters:
    ///     - config: Override `GatekeeperConfig` instead of using the default `app.gatekeeper.config`
    ///     - keyMaker: Override `GatekeeperKeyMaker` instead of using the default `app.gatekeeper.keyMaker`
    ///     - config: Override the `Error` thrown when the user is rate-limited instead of using the default error.
    public init(config: GatekeeperConfig? = nil, keyMaker: GatekeeperKeyMaker? = nil, error: Error? = nil) {
        self.config = config
        self.keyMaker = keyMaker
        self.error = error
    }
    
    public func respond(to request: Request, chainingTo next: Responder) -> EventLoopFuture<Response> {
        let gatekeeper = request.gatekeeper(config: config, keyMaker: keyMaker)
            
        let gatekeep: EventLoopFuture<Gatekeeper.Entry>
        if let error = error {
            gatekeep = gatekeeper.gatekeep(on: request, throwing: error)
        } else {
            gatekeep = gatekeeper.gatekeep(on: request)
        }
        
        return gatekeep.flatMap { entry in
            next.respond(to: request).map { response in
                guard let config = self.config else { return response }

                response.headers.replaceOrAdd(name: "Rate-Limit-Limit", value: "\(config.limit)")
                response.headers.replaceOrAdd(name: "Rate-Limit-Remaining", value: "\(entry.requestsLeft)")

                let expiresAt = entry.createdAt.addingTimeInterval(config.refreshInterval)
                let reset = Int(expiresAt.timeIntervalSince1970 - Date().timeIntervalSince1970)
                response.headers.replaceOrAdd(name: "Rate-Limit-Reset", value: "\(reset)")
                return response
            }
        }
    }
}
