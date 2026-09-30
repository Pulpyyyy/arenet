<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  PathRulesSection (path-based-rules Task 8). Collapsed-by-default
  editor for a route's path-scoped rules: a list of cards, each with
  a path-prefix input, an optional basic-auth override (username +
  password), and an embedded IPFilterFields (Task 7) scoped to that
  prefix. Mirrors the request/response-headers <details> disclosure
  pattern from routes/+page.svelte (collapsed <details>/<summary>,
  count badge in the summary, Button variant="ghost" size="sm" for
  add/remove) rather than inventing a new collapsible affordance.

  IMPORTANT: unlike the route-level basic auth (which has a
  `passwordSet` flag driving a "already set" placeholder), the
  backend does NOT emit `passwordSet` for path-rule basic-auth. Do
  NOT build that affordance here — the password field is a plain
  password input, no placeholder-on-edit trick.

  Two-way bound via Svelte 5 `$bindable` — the parent owns the
  PathRule[] array (route-level formData.pathRules) and this
  component mutates it in place (push/splice), mirroring the
  aliases/upstreams repeaters in routes/+page.svelte.

  Public API (add-only; do not rename/remove props):

    value — the bound PathRule[] list.
-->
<script lang="ts">
	import type { PathRule } from '$lib/api/types';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import Button from '$lib/components/Button.svelte';
	import Input from '$lib/components/Input.svelte';
	import IPFilterFields from './IPFilterFields.svelte';

	interface Props {
		value: PathRule[];
	}

	let { value = $bindable() }: Props = $props();

	function addRule(): void {
		value = [...value, { pathPrefix: '', ipFilter: { mode: 'off' } }];
	}

	function removeRule(i: number): void {
		value = value.filter((_, idx) => idx !== i);
	}

	// v2.44 — mirrors toggleBasicAuth: assign through value[i], not
	// through the each-block alias, so the change propagates.
	function toggleRedirect(i: number, enabled: boolean): void {
		if (enabled) {
			// 302 by default: a landing path is a convenience an
			// application update can change, and a 301 cached by every
			// visitor's browser is remarkably hard to take back.
			value[i].redirect = { target: '', statusCode: 302 };
		} else {
			value[i].redirect = undefined;
		}
	}

	function toggleBasicAuth(i: number, enabled: boolean): void {
		if (enabled) {
			value[i].basicAuth = { username: '', password: '' };
		} else {
			value[i].basicAuth = undefined;
		}
	}

	// Task 6 (per-path upstream routing) — the upstream pool, lbPolicy
	// and healthCheck are all optional/absent on a PathRule that
	// inherits the route's upstream. We only materialise them on
	// first operator interaction so a pool-less rule stays pool-less
	// on submit (sanitizePathRules on the backend drops empty
	// upstream pools; we mirror that "don't create until asked"
	// discipline client-side too).
	// Each mutator writes through the existing rule object in place
	// (mirrors toggleBasicAuth/setIpFilterValue above, and keeps the
	// object identity the parent/test holds intact) and then
	// reassigns `value = value` — a no-op replacement of the
	// top-level bindable array — to force Svelte to re-evaluate the
	// #each block. Plain in-place nested mutation alone triggers a
	// `binding_property_non_reactive` warning and the DOM does not
	// update reliably when `value` was not itself created via
	// `$state` on the caller's side (e.g. a bare array literal passed
	// in tests), because $bindable does not deep-proxy values it did
	// not create.
	function touch(): void {
		value = [...value];
	}

	function addBackend(i: number): void {
		const rule = value[i];
		if (!rule.upstreams) rule.upstreams = [];
		rule.upstreams.push({ url: '', weight: 1 });
		if (!rule.lbPolicy) rule.lbPolicy = 'round_robin';
		touch();
	}

	function removeBackend(i: number, j: number): void {
		const rule = value[i];
		if (!rule.upstreams) return;
		rule.upstreams = rule.upstreams.filter((_, idx) => idx !== j);
		touch();
	}

	function updateBackend(i: number, j: number, patch: Partial<{ url: string; weight: number }>): void {
		const rule = value[i];
		if (!rule.upstreams?.[j]) return;
		Object.assign(rule.upstreams[j], patch);
		touch();
	}

	function setLbPolicy(i: number, lbPolicy: PathRule['lbPolicy']): void {
		value[i].lbPolicy = lbPolicy;
		touch();
	}

	function toggleHealthCheck(i: number, enabled: boolean): void {
		if (enabled) {
			value[i].healthCheck = {
				enabled: true,
				uri: '',
				method: 'GET',
				interval: '10s',
				timeout: '5s',
				expectStatus: 0,
				expectBody: '',
				passes: 1,
				fails: 1
			};
		} else {
			value[i].healthCheck = undefined;
		}
		touch();
	}

	function updateHealthCheckUri(i: number, uri: string): void {
		const rule = value[i];
		if (!rule.healthCheck) return;
		rule.healthCheck.uri = uri;
		touch();
	}

	// v2.23.1 — mirror the route-level weightVisible gate
	// (routes/+page.svelte weightVisible) per path-rule card: the weight
	// input is only meaningful under weighted_round_robin, so hide it
	// otherwise instead of always showing an ignored field.
	function weightVisible(rule: PathRule): boolean {
		return rule.lbPolicy === 'weighted_round_robin';
	}

	// v2.23.1 — the per-path skip-TLS-verify checkbox is only meaningful
	// when the path's own upstream pool has at least one https:// URL
	// (dogfooding finding: showing it unconditionally implied it did
	// something on an http-only pool, which it doesn't).
	function poolIsHttps(rule: PathRule): boolean {
		return !!rule.upstreams?.some((u) => u.url.trim().toLowerCase().startsWith('https://'));
	}

	// IPFilterFields expects a non-optional IPFilter, but PathRule.ipFilter
	// is optional (rules loaded from the API may predate the field). This
	// getter/setter pair lazily materializes an "off" default on first
	// write, without mutating rules that are only being read/rendered.
	function ipFilterValue(rule: PathRule): NonNullable<PathRule['ipFilter']> {
		return rule.ipFilter ?? { mode: 'off' };
	}
	// v2.57 — the per-path rate limit.
	//
	// Its own counters, so a strict limit on a login endpoint does not
	// spend the route's budget and the route's limit does not dilute it.
	// Both apply.
	function rateLimitEnabled(rule: PathRule): boolean {
		return rule.rateLimit != null;
	}

	function toggleRateLimit(rule: PathRule, on: boolean): void {
		rule.rateLimit = on ? { events: 10, window: '1m' } : undefined;
		value = [...value];
	}

	function setIpFilterValue(rule: PathRule, next: NonNullable<PathRule['ipFilter']>): void {
		rule.ipFilter = next;
	}
</script>

<details class="rounded border border-border-subtle" data-testid="path-rules-section">
	<summary class="px-3 py-2 text-sm text-secondary cursor-pointer select-none">
		{language.current && t('routes.pathRules.sectionLabel')}
		{#if value.length > 0}
			<span class="ml-1 text-xs text-muted">({value.length})</span>
		{/if}
	</summary>
	<div class="p-3 flex flex-col gap-3 border-t border-border-subtle">
		<p class="text-xs text-muted">
			{language.current && t('routes.pathRules.sectionHelp')}
		</p>

		{#each value as rule, i (i)}
			<div
				class="flex flex-col gap-3 rounded-md border border-border-default bg-surface p-3"
				data-testid="path-rule-card"
			>
				<div class="flex items-start gap-2">
					<div class="flex-1">
						<Input
							label={language.current && t('routes.pathRules.prefixLabel')}
							bind:value={rule.pathPrefix}
							placeholder={language.current && t('routes.pathRules.prefixPlaceholder')}
							data-testid="path-rule-prefix-{i}"
						/>
						<p class="text-xs text-muted mt-1">
							{language.current && t('routes.pathRules.prefixHelp')}
						</p>
					</div>
					<Button
						variant="ghost"
						size="sm"
						onclick={() => removeRule(i)}
						type="button"
						data-testid="path-rule-remove-{i}"
						aria-label={language.current && t('routes.pathRules.remove')}
					>
						×
					</Button>
				</div>

				<!-- v2.44 — exact match + redirect. Both exist for the
				     same case: an application that serves nothing at its
				     root. "/" as a prefix matches everything, including
				     the redirect's own target, so the exact mode is what
				     makes the rule expressible at all. -->
				<div class="flex flex-col gap-2">
					<label class="inline-flex items-center gap-2 text-sm text-secondary cursor-pointer">
						<input
							type="checkbox"
							class="accent-cyan"
							checked={!!rule.matchExact}
							onchange={(e) => (value[i].matchExact = (e.currentTarget as HTMLInputElement).checked)}
							data-testid="path-rule-exact-toggle-{i}"
						/>
						{language.current && t('routes.pathRules.matchExactLabel')}
					</label>
					<p class="text-xs text-muted">
						{language.current && t('routes.pathRules.matchExactHelp')}
					</p>
				</div>

				<div class="flex flex-col gap-2">
					<label class="inline-flex items-center gap-2 text-sm text-secondary cursor-pointer">
						<input
							type="checkbox"
							class="accent-cyan"
							checked={!!rule.redirect}
							onchange={(e) => toggleRedirect(i, (e.currentTarget as HTMLInputElement).checked)}
							data-testid="path-rule-redirect-toggle-{i}"
						/>
						{language.current && t('routes.pathRules.redirectLabel')}
					</label>
					{#if rule.redirect}
						<div class="flex flex-col gap-2 pl-6" data-testid="path-rule-redirect-{i}">
							<Input
								label={language.current && t('routes.pathRules.redirectTargetLabel')}
								bind:value={value[i].redirect!.target}
								placeholder="/admin/login"
								data-testid="path-rule-redirect-target-{i}"
							/>
							<p class="text-xs text-muted">
								{language.current && t('routes.pathRules.redirectTargetHelp')}
							</p>
							<label class="inline-flex items-center gap-2 text-sm text-secondary">
								{language.current && t('routes.pathRules.redirectCodeLabel')}
								<select
									class="h-9 w-28 rounded-md border border-border-default bg-surface px-2 text-sm text-primary"
									value={String(rule.redirect.statusCode ?? 302)}
									onchange={(e) =>
										value[i].redirect &&
										(value[i].redirect.statusCode = Number(
											(e.currentTarget as HTMLSelectElement).value
										))}
									data-testid="path-rule-redirect-code-{i}"
								>
									<option value="302">302</option>
									<option value="301">301</option>
								</select>
							</label>
							<p class="text-xs text-muted">
								{language.current && t('routes.pathRules.redirectCodeHelp')}
							</p>
						</div>
					{/if}
				</div>

				<div class="flex flex-col gap-2">
					<label class="inline-flex items-center gap-2 text-sm text-secondary cursor-pointer">
						<input
							type="checkbox"
							class="accent-cyan"
							checked={!!rule.basicAuth}
							onchange={(e) => toggleBasicAuth(i, (e.currentTarget as HTMLInputElement).checked)}
							data-testid="path-rule-basicauth-toggle-{i}"
						/>
						{language.current && t('routes.pathRules.basicAuthLabel')}
					</label>
					{#if rule.basicAuth}
						<div class="ml-6 flex flex-col gap-2">
							<Input
								label={language.current && t('routes.pathRules.basicAuthUsernameLabel')}
								bind:value={rule.basicAuth.username}
								placeholder={language.current && t('routes.pathRules.basicAuthUsernamePlaceholder')}
								data-testid="path-rule-basicauth-username-{i}"
							/>
							<div>
								<label
									for="path-rule-basicauth-password-{i}"
									class="text-sm font-medium text-secondary block mb-1"
								>
									{language.current && t('routes.pathRules.basicAuthPasswordLabel')}
								</label>
								<input
									id="path-rule-basicauth-password-{i}"
									type="password"
									bind:value={
										() => rule.basicAuth?.password ?? '',
										(v) => {
											if (rule.basicAuth) rule.basicAuth.password = v;
										}
									}
									data-testid="path-rule-basicauth-password-{i}"
									class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
								/>
							</div>
						</div>
					{/if}
				</div>

				<div>
					<span class="text-xs font-medium text-secondary block mb-1">
						{language.current && t('routes.pathRules.ipFilterLabel')}
					</span>
					<IPFilterFields
						bind:value={
							() => ipFilterValue(rule),
							(next) => setIpFilterValue(rule, next)
						}
					/>
				</div>

				<!-- v2.57 — a stricter limit for this path only.
				     The route's own limit is unchanged and still applies: the
				     two are separate counter zones, so protecting one login
				     endpoint does not mean throttling every asset on the
				     page. -->
				<div>
					<label class="flex items-center gap-2 text-xs font-medium text-secondary mb-1">
						<input
							type="checkbox"
							checked={rateLimitEnabled(rule)}
							onchange={(e) => toggleRateLimit(rule, (e.currentTarget as HTMLInputElement).checked)}
							data-testid="path-rule-rate-limit-toggle-{i}"
						/>
						{language.current && t('routes.pathRules.rateLimitLabel')}
					</label>
					{#if rule.rateLimit}
						<div class="grid grid-cols-1 sm:grid-cols-3 gap-2 pl-6">
							<div>
								<label
									for="path-rate-events-{i}"
									class="text-[11px] text-muted block mb-0.5"
								>
									{language.current && t('routes.pathRules.rateLimitEvents')}
								</label>
								<input
									id="path-rate-events-{i}"
									type="number"
									min="1"
									bind:value={rule.rateLimit.events}
									data-testid="path-rule-rate-events-{i}"
									class="w-full h-8 rounded border border-border-default bg-surface px-2 text-sm text-primary"
								/>
							</div>
							<div>
								<label
									for="path-rate-window-{i}"
									class="text-[11px] text-muted block mb-0.5"
								>
									{language.current && t('routes.pathRules.rateLimitWindow')}
								</label>
								<input
									id="path-rate-window-{i}"
									type="text"
									placeholder="1m"
									bind:value={rule.rateLimit.window}
									data-testid="path-rule-rate-window-{i}"
									class="w-full h-8 rounded border border-border-default bg-surface px-2 text-sm text-primary font-mono"
								/>
							</div>
							<div>
								<label for="path-rate-key-{i}" class="text-[11px] text-muted block mb-0.5">
									{language.current && t('routes.pathRules.rateLimitKey')}
								</label>
								<input
									id="path-rate-key-{i}"
									type="text"
									placeholder="{'{http.request.remote.host}'}"
									bind:value={rule.rateLimit.key}
									data-testid="path-rule-rate-key-{i}"
									class="w-full h-8 rounded border border-border-default bg-surface px-2 text-sm text-primary font-mono"
								/>
							</div>
						</div>
						<p class="text-[11px] text-muted mt-1 pl-6">
							{language.current && t('routes.pathRules.rateLimitHint')}
						</p>
					{/if}
				</div>

				<!-- Task 6 (per-path upstream routing) — collapsed-by-default
				     disclosure mirroring the route-level health-check <details>
				     idiom. Only forced open when the rule already carries a
				     non-empty pool on mount (mirrors open={formData.healthCheck.enabled}
				     at routes/+page.svelte:4189). -->
				<details
					class="rounded border border-border-subtle"
					open={(rule.upstreams?.length ?? 0) > 0}
					data-testid="path-rule-upstream-disclosure-{i}"
				>
					<summary class="px-3 py-2 text-sm text-secondary cursor-pointer select-none">
						{language.current && t('routes.pathRules.upstreamLabel')}
						{#if rule.upstreams && rule.upstreams.length > 0}
							<span
								class="ml-1 text-xs text-muted"
								data-testid="path-rule-backends-badge-{i}"
							>
								{language.current &&
									t('routes.pathRules.upstreamBackendsBadge', {
										count: rule.upstreams.length
									})}
							</span>
						{/if}
					</summary>
					<div class="p-3 flex flex-col gap-3 border-t border-border-subtle">
						<p class="text-xs text-muted">
							{language.current && t('routes.pathRules.upstreamInheritHint')}
						</p>

						{#if rule.upstreams}
							{#each rule.upstreams as _backend, j (j)}
								<div class="flex items-start gap-2">
									<div class="flex-1">
										<Input
											bind:value={
												() => rule.upstreams?.[j]?.url ?? '',
												(v) => updateBackend(i, j, { url: v })
											}
											placeholder={language.current &&
												t('routes.pathRules.upstreamUrlPlaceholder')}
											data-testid="path-rule-upstream-url-{i}-{j}"
										/>
									</div>
									{#if weightVisible(rule)}
										<div class="w-24">
											<label for="path-rule-upstream-weight-{i}-{j}" class="sr-only">
												{language.current && t('routes.pathRules.upstreamWeightLabel')}
											</label>
											<input
												id="path-rule-upstream-weight-{i}-{j}"
												type="number"
												min="1"
												value={rule.upstreams?.[j]?.weight ?? 1}
												oninput={(e) =>
													updateBackend(i, j, {
														weight: Number((e.currentTarget as HTMLInputElement).value) || 1
													})}
												placeholder={language.current &&
													t('routes.pathRules.upstreamWeightLabel')}
												data-testid="path-rule-upstream-weight-{i}-{j}"
												class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
											/>
										</div>
									{/if}
									<Button
										variant="ghost"
										size="sm"
										onclick={() => removeBackend(i, j)}
										type="button"
										data-testid="path-rule-upstream-remove-{i}-{j}"
										aria-label={language.current &&
											t('routes.pathRules.upstreamRemoveBackend')}
									>
										×
									</Button>
								</div>
							{/each}
						{/if}

						<Button
							variant="ghost"
							size="sm"
							onclick={() => addBackend(i)}
							type="button"
							data-testid="path-rule-upstream-add-{i}"
						>
							{language.current && t('routes.pathRules.upstreamAddBackend')}
						</Button>

						{#if rule.upstreams && rule.upstreams.length > 0}
							<div>
								<label for="path-rule-lb-{i}" class="text-sm font-medium text-secondary block mb-1">
									{language.current && t('routes.pathRules.upstreamLbLabel')}
								</label>
								<select
									id="path-rule-lb-{i}"
									value={rule.lbPolicy ?? 'round_robin'}
									onchange={(e) =>
										setLbPolicy(i, (e.currentTarget as HTMLSelectElement).value as PathRule['lbPolicy'])}
									data-testid="path-rule-lb-{i}"
									class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
								>
									<option value="round_robin"
										>{language.current && t('routes.form.lbRoundRobin')}</option
									>
									<option value="weighted_round_robin"
										>{language.current && t('routes.form.lbWeightedRoundRobin')}</option
									>
									<option value="least_conn"
										>{language.current && t('routes.form.lbLeastConn')}</option
									>
									<option value="ip_hash"
										>{language.current && t('routes.form.lbIPHash')}</option
									>
									<option value="random">{language.current && t('routes.form.lbRandom')}</option>
									<option value="first">{language.current && t('routes.form.lbFirst')}</option>
								</select>
							</div>
						{/if}

						<div class="flex flex-col gap-2">
							<label class="inline-flex items-center gap-2 text-sm text-secondary cursor-pointer">
								<input
									type="checkbox"
									class="accent-cyan"
									checked={!!rule.healthCheck?.enabled}
									onchange={(e) =>
										toggleHealthCheck(i, (e.currentTarget as HTMLInputElement).checked)}
									data-testid="path-rule-hc-toggle-{i}"
								/>
								{language.current && t('routes.pathRules.upstreamHealthCheckLabel')}
							</label>
							{#if rule.healthCheck?.enabled}
								<div class="ml-6">
									<Input
										bind:value={
											() => rule.healthCheck?.uri ?? '',
											(v) => updateHealthCheckUri(i, v)
										}
										placeholder={language.current &&
											t('routes.pathRules.upstreamHealthCheckUriPlaceholder')}
										data-testid="path-rule-hc-uri-{i}"
									/>
								</div>
							{/if}
						</div>

						{#if rule.upstreams && rule.upstreams.length > 0 && poolIsHttps(rule)}
							<label class="inline-flex items-center gap-2 text-sm text-secondary cursor-pointer">
								<input
									type="checkbox"
									class="accent-cyan"
									checked={!!rule.insecureSkipVerify}
									onchange={(e) =>
										(value[i].insecureSkipVerify = (e.currentTarget as HTMLInputElement).checked)}
									data-testid="path-rule-skip-verify-{i}"
								/>
								{language.current && t('routes.pathRules.upstreamSkipVerifyLabel')}
							</label>
						{/if}
					</div>
				</details>
			</div>
		{/each}

		<Button variant="ghost" size="sm" onclick={addRule} type="button" data-testid="path-rules-add">
			{language.current && t('routes.pathRules.add')}
		</Button>
	</div>
</details>
