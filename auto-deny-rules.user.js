// ==UserScript==
// @name         Auto Deny Rules
// @namespace    illumio
// @version      1.4
// @description  Automatically generate and manage deny rules
// @match        *://*/*/rulesets*
// @updateURL    https://raw.githubusercontent.com/code7a/auto-deny-rules-dev/main/auto-deny-rules.user.js
// @downloadURL  https://raw.githubusercontent.com/code7a/auto-deny-rules-dev/main/auto-deny-rules.user.js
// @grant        none
// ==/UserScript==

/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

(function() {
    'use strict';

    const log = (...args) => console.log('🤖 Auto Deny:', ...args);
    const logJSON = (label, data) => {
        try {
            console.log(`🤖 Auto Deny: ${label} (compact JSON):`, JSON.stringify(data));
        } catch (e) {
            console.error('❌ Auto Deny: Failed to stringify', label, e, data);
        }
    };

    const baseUrl = window.location.origin;
    let orgId = null, btn = null;

    // --- CSRF token ---
    const getCsrfToken = () => {
        const match = document.cookie.match(/(?:^|;\s*)csrf_token=([^;]+)/);
        if (!match) return null;
        const raw = decodeURIComponent(match[1]);
        return raw.replace(/^"|"$/g, '');
    };

    // --- Detect org ID dynamically ---
    const detectOrgId = url => {
        if (!orgId) {
            const match = url?.match(/\/api\/v2\/orgs\/(\d+)(\/|$)/);
            if (match) {
                orgId = match[1];
                log('✅ Detected org ID dynamically:', orgId);
            }
        }
    };

    const origFetch = window.fetch;
    window.fetch = function(...args) {
        detectOrgId(typeof args[0] === 'string' ? args[0] : args[0]?.url);
        return origFetch.apply(this, args);
    };

    const origOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url, ...rest) {
        detectOrgId(url);
        return origOpen.apply(this, [method, url, ...rest]);
    };

    async function waitForOrgId(timeoutMs = 8000) {
        const start = Date.now();
        while (!orgId && Date.now() - start < timeoutMs) {
            await new Promise(r => setTimeout(r, 100));
        }
        if (!orgId) throw new Error('Org ID not detected');
    }

    // --- Fetch JSON with logging ---
    async function fetchJSON(url, options = {}) {
        try {
            const resp = await fetch(url, options);
            const text = await resp.text();
            let data = null;
            if (text) {
                try {
                    data = JSON.parse(text);
                } catch {
                    /* non-JSON */
                }
            }
            if (!resp.ok) {
                console.warn('⚠️ Non-OK response', resp.status, resp.statusText, url, data);
            }
            logJSON(`Response from ${url}`, data);
            return data;
        } catch (e) {
            console.error('❌ Fetch error:', e, url);
            return null;
        }
    }

    // --- Name formatting ---
    function formatRulesetName() {
        const now = new Date();
        const monthNames = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
        const pad = n => String(n).padStart(2, '0');
        const month = monthNames[now.getMonth()];
        const day = pad(now.getDate());
        const year = now.getFullYear();
        const hh = pad(now.getHours());
        const mm = pad(now.getMinutes());
        const ss = pad(now.getSeconds());
        return `Auto Deny Rules - ${month} ${day}, ${year} ${hh}:${mm}:${ss}`;
    }

    // --- Create new ruleset ---
    async function createNewRuleset() {
        const name = formatRulesetName();
        const payload = { name, description: 'created by auto-deny-rules', scopes: [[]] };
        logJSON('📤 Payload for creating new ruleset', payload);

        const res = await fetch(`${baseUrl}/api/v2/orgs/${orgId}/sec_policy/draft/rule_sets`, {
            method: 'POST',
            keepalive: true,
            headers: {
                'Content-Type': 'application/json',
                'x-csrf-token': getCsrfToken()
            },
            body: JSON.stringify(payload),
            credentials: 'include'
        });

        log('📡 Response status:', res.status, res.statusText);

        const text = await res.text();
        const data = text ? JSON.parse(text) : null;
        logJSON('📥 Response body', data);

        if (!res.ok) throw new Error(`Failed creating ruleset: ${res.status}`);
        log('✅ Created new ruleset:', data.name, data.href);

        if (btn) {
            btn.style.transition = 'opacity 0.5s';
            btn.style.opacity = 0;
            btn.disabled = true;
        }

        if (data?.href) {
            await new Promise(r => setTimeout(r, 1000));
            const match = data.href.match(/\/rule_sets\/(\d+)/);
            if (match) {
                const rulesetId = match[1];
                window.location.href = `${baseUrl}/#/rulesets/${rulesetId}/draft/intrascope`;
                log(`➡️ Redirecting to new ruleset: ${window.location.href}`);
            }
        }

        return data?.href;
    }

    // --- Fetch supporting data ---
    async function fetchSupportingData() {
        const ransomwareServices = await fetchJSON(`${baseUrl}/api/v2/orgs/${orgId}/sec_policy/active/services?is_ransomware=true`);
        const anyIPList = await fetchJSON(`${baseUrl}/api/v2/orgs/${orgId}/sec_policy/draft/ip_lists?name=${encodeURIComponent('Any (0.0.0.0/0 and ::/0)')}`);
        const envs = await fetchJSON(`${baseUrl}/api/v2/orgs/${orgId}/labels?key=env`);
        const envData = [];

        for (const env of envs || []) {
            const workloads = await fetchJSON(`${baseUrl}/api/v2/orgs/${orgId}/workloads?managed=true&online=true&labels=${encodeURIComponent(`[["${env.href}"]]`)}&enforcement_modes=${encodeURIComponent('["selective","visibility_only"]')}`);
            const apps = [...new Map(
                (workloads || [])
                    .flatMap(w => w.labels || [])
                    .filter(l => l.key === 'app')
                    .map(l => [l.href, { href: l.href, name: l.value }])
            ).values()];
            envData.push({ env, apps });
            logJSON(`Unique apps for env ${env.value}`, apps.map(a => a.name));
        }

        return { ransomwareServices, anyIPList, envData };
    }

    // --- Get service ports/protocols ---
    async function getServicePorts(serviceHref) {
        const svc = await fetchJSON(`${baseUrl}/api/v2${serviceHref}`);
        return (svc?.service_ports || []).map(p => ({ port: p.port, proto: p.proto }));
    }

    // --- Poll helper with backoff ---
    async function pollUntilCompleted(href, maxWaitMs = 120000) {
        const start = Date.now();
        let delay = 1500;
        while (Date.now() - start < maxWaitMs) {
            const poll = await fetchJSON(`${baseUrl}/api/v2${href}`, {
                headers: { 'x-csrf-token': getCsrfToken() },
                credentials: 'include'
            });
            const status = poll?.status;
            if (status === 'completed') return true;
            if (status === 'failed' || status === 'canceled') return false;
            await new Promise(r => setTimeout(r, delay));
            delay = Math.min(delay * 1.5, 6000);
        }
        return false;
    }

    // --- Submit sequential traffic query ---
    async function submitTrafficQuery(envHref, appHref, ports) {
        const now = new Date().toISOString();
        const start24h = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
        const start89d = new Date(Date.now() - 89 * 24 * 60 * 60 * 1000).toISOString();

        const basePayload = (start, end) => ({
            sources: { include: [[]], exclude: [] },
            destinations: { include: [[{ "label": { "href": envHref } }, { "label": { "href": appHref } }]], exclude: [] },
            services: { include: ports, exclude: [] },
            sources_destinations_query_op: "and",
            start_date: start,
            end_date: end,
            policy_decisions: ["allowed", "potentially_blocked", "unknown"],
            boundary_decisions: [],
            query_name: "",
            exclude_workloads_from_ip_list_query: false,
            max_results: 1
        });

        // 24h query
        const resp24 = await fetchJSON(`${baseUrl}/api/v2/orgs/${orgId}/traffic_flows/async_queries`, {
            method: 'POST',
            keepalive: true,
            headers: {
                'Content-Type': 'application/json',
                'x-csrf-token': getCsrfToken()
            },
            body: JSON.stringify(basePayload(start24h, now)),
            credentials: 'include'
        });

        if (resp24?.href) {
            const ok = await pollUntilCompleted(resp24.href);
            if (ok) {
                const download = await fetchJSON(`${baseUrl}/api/v2${resp24.href}/download`, {
                    headers: { 'x-csrf-token': getCsrfToken(), 'Accept': 'application/json' },
                    credentials: 'include'
                });
                if (download?.length) return true;
            }
        }

        // 89d query
        const resp89 = await fetchJSON(`${baseUrl}/api/v2/orgs/${orgId}/traffic_flows/async_queries`, {
            method: 'POST',
            keepalive: true,
            headers: {
                'Content-Type': 'application/json',
                'x-csrf-token': getCsrfToken()
            },
            body: JSON.stringify(basePayload(start89d, now)),
            credentials: 'include'
        });

        if (resp89?.href) {
            const ok = await pollUntilCompleted(resp89.href);
            if (ok) {
                const download = await fetchJSON(`${baseUrl}/api/v2${resp89.href}/download`, {
                    headers: { 'x-csrf-token': getCsrfToken(), 'Accept': 'application/json' },
                    credentials: 'include'
                });
                return !(download?.length);
            }
        }

        return false;
    }

    // --- Dedup helper ---
    function uniqByHref(items) {
        const seen = new Set();
        return items.filter(i => {
            const h = i.label?.href || i.ip_list?.href || i.href;
            if (!h || seen.has(h)) return false;
            seen.add(h);
            return true;
        });
    }

    // --- Create deny rule ---
    async function createDenyRule(rulesetHref, anyIPHref, serviceHref, appHrefs, envHref) {
        const providers = uniqByHref([
            ...appHrefs.map(h => ({ label: { href: h } })),
            { label: { href: envHref } }
        ]);

        const payload = {
            providers,
            consumers: [{ ip_list: { href: anyIPHref } }],
            enabled: true,
            ingress_services: [{ href: serviceHref }]
        };

        logJSON('📤 Payload for creating deny rule', payload);

        const res = await fetch(`${baseUrl}/api/v2${rulesetHref}/deny_rules`, {
            method: 'POST',
            keepalive: true,
            headers: {
                'Content-Type': 'application/json',
                'x-csrf-token': getCsrfToken()
            },
            body: JSON.stringify(payload),
            credentials: 'include'
        });

        log('📡 Deny rule creation response status:', res.status, res.statusText);

        setTimeout(() => {
            window.scrollTo({ top: document.body.scrollHeight, behavior: 'smooth' });
        }, 1000);
    }

    // --- Main run ---
    async function runAutoDeny() {
        try {
            await waitForOrgId();

            const hash = window.location.hash;
            if (/^#\/rulesets\/.*\/draft\//.test(hash)) {
                console.log('🤖 Auto Deny: Draft page detected, skipping script.');
                if (btn) btn.style.display = 'none';
                return;
            }

            const rulesetHref = await createNewRuleset();
            const { ransomwareServices, anyIPList, envData } = await fetchSupportingData();

            if (!ransomwareServices?.length) {
                console.warn('⚠️ No ransomware services found');
                return;
            }

            const anyIPHref = anyIPList?.[0]?.href;
            if (!anyIPHref) {
                console.error('❌ Any IP list not found');
                return;
            }

            let totalCombinations = 0;
            for (const s of (ransomwareServices || [])) {
                totalCombinations += (envData || []).reduce((acc, e) => acc + (e.apps?.length || 0), 0);
            }
            totalCombinations = Math.max(totalCombinations, 1);

            let completed = 0;

            for (const service of ransomwareServices || []) {
                const ports = await getServicePorts(service.href);
                for (const envObj of envData || []) {
                    const apps = envObj.apps || [];
                    const zeroFlowApps = [];

                    for (let i = 0; i < apps.length; i += 2) {
                        const batch = apps.slice(i, i + 2);
                        const results = await Promise.all(batch.map(async (app) => {
                            completed++;
                            const percent = ((completed / totalCombinations) * 100).toFixed(1);
                            log(`⏳ Processing Env: ${envObj.env.value}, App: ${app.name}, Service: ${service.name}, Progress: ${percent}%`);
                            const noFlow = await submitTrafficQuery(envObj.env.href, app.href, ports);
                            return noFlow ? app.href : null;
                        }));

                        const appsToDeny = results.filter(x => x);
                        zeroFlowApps.push(...appsToDeny);
                    }

                    if (zeroFlowApps.length) {
                        await createDenyRule(rulesetHref, anyIPHref, service.href, zeroFlowApps, envObj.env.href);
                    }
                }
            }

            log('✅ Auto-deny run complete');
        } catch (e) {
            console.error('❌ Error in runAutoDeny:', e);
        }
    }

    // --- Add button ---
    function addButton() {
        const container = document.querySelector('body');
        if (!container) return;

        btn = document.createElement('button');
        btn.textContent = 'Auto Deny Rules';
        Object.assign(btn.style, {
            position: 'fixed',
            bottom: '20px',
            right: '20px',
            zIndex: 9999,
            padding: '10px 20px',
            backgroundColor: '#ff6600',
            color: '#fff',
            border: 'none',
            borderRadius: '5px',
            cursor: 'pointer',
            boxShadow: '0 2px 6px rgba(0,0,0,0.3)'
        });

        btn.addEventListener('click', () => {
            log('🟢 Button clicked');
            runAutoDeny();
        });

        container.appendChild(btn);
    }

    setTimeout(addButton, 2000);
})();
