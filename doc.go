// Package netloom provides a network automation runtime for caller-authorized
// HTTP/HTTPS requests, streaming responses, and scheduled task pipelines.
//
// New constructs an Engine. Send buffers and closes the underlying response;
// callers of SendStream must close the returned Body. Close cancels engine work
// and waits for it to exit. Callers must drain Run's result channel or cancel its
// context, and must not mutate request or configuration inputs during use.
//
// Compatibility defaults require explicit choices: request TLS verification is
// disabled unless VerifyTLS is set, and Config.Retries equal to zero selects the
// default retries rather than disabling them. A negative value disables retries.
// Direct dialing rejects loopback, unspecified, and link-local addresses but
// allows private networks; callers remain responsible for target authorization.
//
// Offline snapshots and analysis, scanning extensions, API-query clients, and
// MITM primitives live in separate subpackages. The runtime does not provide
// credential storage, business persistence, an HTTP service, or a user interface.
package netloom
