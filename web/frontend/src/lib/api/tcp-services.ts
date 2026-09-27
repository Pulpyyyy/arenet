// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// v2.42 — typed wrappers for the TCP (layer 4) services endpoints:
//   - GET    /api/v1/tcp-services            (viewer)
//   - GET    /api/v1/tcp-services/{id}       (viewer)
//   - POST   /api/v1/tcp-services            (admin)
//   - PUT    /api/v1/tcp-services/{id}       (admin)
//   - DELETE /api/v1/tcp-services/{id}       (admin)
//   - POST   /api/v1/tcp-services/{id}/test  (admin)
//
// Backend mirror: internal/api/tcpservices.go.

import { request } from './client';

/**
 * Load-balancing policies caddy-l4 actually implements
 * (modules/l4proxy/loadbalancing.go). There is no weighted policy at
 * layer 4, which is why a backend carries no weight.
 */
export const TCP_LB_POLICIES = ['round_robin', 'least_conn', 'ip_hash', 'first', 'random'] as const;
export type TCPLBPolicy = (typeof TCP_LB_POLICIES)[number];

/** PROXY protocol versions the relay may prepend. '' = none. */
export const PROXY_PROTOCOL_VERSIONS = ['', 'v1', 'v2'] as const;
export type ProxyProtocolVersion = (typeof PROXY_PROTOCOL_VERSIONS)[number];

export interface TCPUpstream {
	host: string;
	port: number;
	/** Cap on simultaneous connections to this backend. 0 = unlimited. */
	maxConnections?: number;
}

/**
 * Active health check. At layer 4 there is no request to send:
 * connecting to the backend IS the check.
 */
export interface TCPHealthCheck {
	enabled: boolean;
	interval?: string;
	timeout?: string;
}

export interface TCPServiceIPFilter {
	mode: 'off' | 'allow' | 'deny';
	cidrs?: string[];
	statusCode?: number;
}

/** Transports a relay can carry. Empty means tcp. */
export const TCP_SERVICE_PROTOCOLS = ['tcp', 'udp'] as const;
export type TCPServiceProtocol = (typeof TCP_SERVICE_PROTOCOLS)[number];

/**
 * Application protocols a relay can be told to accept, per TRANSPORT
 * (v2.49). Mirror of `acceptProtocolTransports` in
 * internal/storage/tcpservice.go, which is the source of truth and is
 * what the API validates against.
 *
 * Offering a pair the backend refuses would only earn a 400 — but the
 * reason the table is transport-aware is sharper than that: the gate is
 * emitted as `not(<matcher>)`, so a matcher that can never see this
 * transport's traffic refuses EVERY connection. Do not widen a row
 * without widening the Go table first.
 *
 * `quic` and the SOCKS matchers exist in caddy-l4 and are deliberately
 * absent — see the Go file for why.
 */
export const ACCEPT_PROTOCOLS: Record<TCPServiceProtocol, readonly string[]> = {
	tcp: ['tls', 'ssh', 'http', 'postgres', 'rdp', 'xmpp', 'winbox', 'dns', 'openvpn'],
	udp: ['wireguard', 'dns', 'openvpn']
};

/** Protocols valid for a transport; '' (accept anything) is added by the form. */
export const acceptProtocolsFor = (transport: TCPServiceProtocol | undefined): readonly string[] =>
	ACCEPT_PROTOCOLS[transport === 'udp' ? 'udp' : 'tcp'];

/** Causes a connection can be refused for, in `TCPServiceCounters.refused`. */
export const REFUSAL_CAUSES = ['protocol', 'ipFilter', 'crowdsec'] as const;
export type RefusalCause = (typeof REFUSAL_CAUSES)[number];

export interface TCPService {
	id: string;
	name: string;
	/** Empty means every interface. */
	listenAddr?: string;
	listenPort: number;
	/**
	 * Transport to relay; empty means tcp. UDP is what WireGuard,
	 * DNS, syslog and most game servers need. Two pairings the API
	 * refuses: PROXY protocol v1 over UDP (v1 carries no UDP
	 * address) and an active health check over UDP (dialling a UDP
	 * socket always succeeds, so the check could never fail).
	 */
	protocol?: TCPServiceProtocol;
	/**
	 * Application protocol accepted at the handshake — a caddy-l4
	 * matcher name. Empty accepts anything, which is what every service
	 * did before v2.49. A connection whose handshake is not that
	 * protocol is closed and counted under cause `protocol`.
	 *
	 * NOT the same axis as `protocol` above, which is the transport.
	 */
	acceptProtocol?: string;
	upstreams: TCPUpstream[];
	lbPolicy?: TCPLBPolicy;
	healthCheck?: TCPHealthCheck;
	/**
	 * Prepends the PROXY header so the backend sees the real client
	 * IP. The backend must be configured to expect it — a mismatch
	 * breaks connections silently, which is why the form pairs the
	 * two and offers the dial test.
	 */
	proxyProtocol?: ProxyProtocolVersion;
	ipFilter?: TCPServiceIPFilter;
	crowdSecEnabled?: boolean;
	disabled?: boolean;
	createdAt: string;
	updatedAt: string;
}

/** What a create / update sends; the server assigns id and dates. */
export type TCPServiceRequest = Omit<TCPService, 'id' | 'createdAt' | 'updatedAt'>;

/**
 * What the backend did with the PROXY header the test sent it.
 *
 * 'not-refused' rather than 'accepted' on purpose: a single
 * connection can establish that the far side did not hang up, not
 * that it parsed the header. See tcpProxyProbe in the Go handler.
 */
export type ProxyProbeVerdict = 'not-refused' | 'refused';

export interface TCPBackendResult {
	backend: string;
	ok: boolean;
	/** The dial failure, or the reason a backend was skipped. */
	error?: string;
	elapsedMs: number;
	/** UDP: there is no connection to open, so nothing was measured. */
	skipped?: boolean;
	/** v2.46 — the reason in translatable form; `error` is the fallback. */
	errorCode?: string;
	/** Absent when the service sends no header. */
	proxyProtocol?: ProxyProbeVerdict;
}

export interface TCPServiceTestResult {
	backends: TCPBackendResult[];
	/** Present when the service sends a PROXY header. */
	proxyProtocolNote?: string;
	/** v2.46 — lets the UI compose that note in the operator's language. */
	proxyProtocolVersion?: string;
}

export const listTCPServices = (): Promise<TCPService[]> =>
	request<TCPService[]>('GET', '/tcp-services');

export const getTCPService = (id: string): Promise<TCPService> =>
	request<TCPService>('GET', `/tcp-services/${id}`);

export const createTCPService = (svc: TCPServiceRequest): Promise<TCPService> =>
	request<TCPService>('POST', '/tcp-services', svc);

export const updateTCPService = (id: string, svc: TCPServiceRequest): Promise<TCPService> =>
	request<TCPService>('PUT', `/tcp-services/${id}`, svc);

export const deleteTCPService = (id: string): Promise<void> =>
	request<void>('DELETE', `/tcp-services/${id}`);

/** Dials every backend and reports what happened. Changes nothing. */
export const testTCPService = (id: string): Promise<TCPServiceTestResult> =>
	request<TCPServiceTestResult>('POST', `/tcp-services/${id}/test`);

/**
 * What a relay has carried since the process started. Layer-4
 * traffic does not cross the HTTP chain, so these counters are the
 * only view of it — they appear in no route metric and no log.
 */
export interface TCPServiceCounters {
	connections: number;
	/** Open right now. */
	active: number;
	bytesIn: number;
	bytesOut: number;
	/** Connections the relay could not complete. */
	errors: number;
	/**
	 * Connections a gate closed before the backend, keyed by cause.
	 * Absent when nothing was refused; a cause that never fired is
	 * left out rather than sent as 0.
	 *
	 * NOT a subset of `connections`: a refused connection never reaches
	 * the relay, so it is counted here and nowhere else.
	 */
	refused?: Partial<Record<RefusalCause, number>>;
	lastConnectionAt?: string;
}

/** Counters keyed by service id. A service absent from the map has
 *  not been mounted since the last apply. */
export const tcpServicesMetrics = (): Promise<Record<string, TCPServiceCounters>> =>
	request<Record<string, TCPServiceCounters>>('GET', '/tcp-services/metrics');
