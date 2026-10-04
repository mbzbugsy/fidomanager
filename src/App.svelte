<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { onMount } from 'svelte';
  import logoUrl from './assets/fidomanager-logo.png';

  type InspectionSnapshot = {
    epoch: string;
    authenticator: string;
    assessment: {
      completeness: 'complete' | 'incomplete' | 'inconsistent';
      total: { kind: 'exact' | 'at_least' | 'unknown'; value?: number };
      duplicate_rps: boolean;
      duplicate_credentials: boolean;
      count_contradiction: boolean;
    };
    rps: {
      verifiedText: string | null;
      issue: string | null;
      credentials: {
        handle: string;
        userName: string | null;
        displayName: string | null;
      }[];
    }[];
  };
  type FoundationStatus = {
    inspection: InspectionSnapshot | null;
    phase: string;
    workerProtocolVersion: number;
    reviewedLibfido2Baseline: string;
    authenticationNotice: string | null;
    authenticationNoticeRevision: string;
  };

  type AuthenticatorOption = {
    name: string;
    enabled: boolean;
  };

  type Authenticator = {
    displayName: string;
    displayDetail: string;
    handle: string;
    generation: string;
    vendorId: number;
    productId: number;
    manufacturer: string | null;
    product: string | null;
    aaguid: string | null;
    versions: string[];
    extensions: string[];
    transports: string[];
    options: AuthenticatorOption[];
    maxMessageSize: string | null;
    firmwareVersion: string | null;
    readStatus: string;
    freshness: string;
    pinCheckPassed: boolean;
  };

  type AuthenticatorList = {
    enumerationEpoch: string;
    devices: Authenticator[];
  };

  let foundation: FoundationStatus | null = null;
  let snapshot: AuthenticatorList | null = null;
  let discoveryError: string | null = null;
  let refreshing = false;
  let manualScanning = false;
  let lastScan: string | null = null;
  let stopped = false;
  let timer: ReturnType<typeof setTimeout> | null = null;
  let foundationTimer: ReturnType<typeof setTimeout> | null = null;
  let activeNoticeRevision: string | null = null;
  let noticeVisible = false;
  let noticeTimer: ReturnType<typeof setTimeout> | null = null;

  const pollDelayMs = 1000;

  function updateNotice(revision: string | null, message: string | null) {
    if (revision === activeNoticeRevision) return;
    activeNoticeRevision = revision;
    if (noticeTimer) clearTimeout(noticeTimer);
    noticeVisible = Boolean(message);
    if (noticeVisible) {
      noticeTimer = setTimeout(() => {
        noticeVisible = false;
      }, 10_000);
    }
  }

  function dismissNotice() {
    noticeVisible = false;
    if (noticeTimer) clearTimeout(noticeTimer);
  }

  $: updateNotice(
    foundation?.authenticationNoticeRevision ?? null,
    foundation?.authenticationNotice ?? null,
  );

  function hex16(value: number) {
    return value.toString(16).padStart(4, '0');
  }

  function friendlyStatus(status: string) {
    return status
      .replace(/_/g, ' ')
      .replace(/([a-z])([A-Z])/g, '$1 $2')
      .toLowerCase();
  }

  async function loadFoundation() {
    try {
      foundation = await invoke<FoundationStatus>('foundation_status');
    } catch {
      foundation = null;
    } finally {
      if (!stopped) {
        foundationTimer = setTimeout(() => void loadFoundation(), pollDelayMs);
      }
    }
  }

  async function refreshDevices(scheduleNext = true, manual = false) {
    if (refreshing || stopped) return;
    refreshing = true;
    if (manual) {
      manualScanning = true;
    }

    try {
      snapshot = await invoke<AuthenticatorList>('list_authenticators');
      discoveryError = null;
      lastScan = new Date().toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      });
    } catch (error) {
      snapshot = null;
      discoveryError =
        typeof error === 'string' ? error : 'Native discovery is unavailable.';
    } finally {
      refreshing = false;
      if (manual) {
        manualScanning = false;
      }
      if (scheduleNext && !stopped) {
        timer = setTimeout(() => void refreshDevices(), pollDelayMs);
      }
    }
  }

  function refreshNow() {
    if (timer) clearTimeout(timer);
    timer = null;
    void refreshDevices(true, true);
  }

  onMount(() => {
    stopped = false;
    void loadFoundation();
    void refreshDevices();
    return () => {
      stopped = true;
      if (timer) clearTimeout(timer);
      if (foundationTimer) clearTimeout(foundationTimer);
      if (noticeTimer) clearTimeout(noticeTimer);
    };
  });
</script>

<svelte:head>
  <title>Fido Manager</title>
</svelte:head>

<div class="app-frame">
  <header class="topbar">
    <div class="brand" aria-label="Fido Manager">
      <img class="brand-logo" src={logoUrl} alt="" />
      <strong>Fido Manager</strong>
    </div>

    <div class="toolbar" role="toolbar" aria-label="Actions">
      <span class="mode-pill" title="No changes can be made to authenticators">
        <i></i> Read-only
      </span>
      <span class="toolbar-divider" aria-hidden="true"></span>
      <button
        class="tool-button"
        type="button"
        onclick={() => refreshNow()}
        disabled={manualScanning}
      >
        <svg viewBox="0 0 24 24" aria-hidden="true">
          <path d="M20 7v5h-5M4 17v-5h5" />
          <path d="M6.1 8.2A7 7 0 0 1 18.8 7M17.9 15.8A7 7 0 0 1 5.2 17" />
        </svg>
        {manualScanning ? 'Scanning…' : 'Scan now'}
      </button>
    </div>
  </header>

  <main class="workspace">
    <section class="page-head" aria-labelledby="page-title">
      <div class="page-title">
        <h1 id="page-title">Authenticators</h1>
        <span class="device-count"
          >{snapshot?.devices.length ?? 0} connected</span
        >
      </div>

      <div class="status-line-inline" aria-label="System status">
        <span class="status-item">
          <i aria-hidden="true" class:warning={Boolean(discoveryError)}></i>
          Native service
          <strong>{discoveryError ? 'attention' : 'online'}</strong>
        </span>
        <span class="status-item">
          libfido2 <strong>{foundation?.reviewedLibfido2Baseline ?? '—'}</strong
          >
        </span>
      </div>
    </section>

    {#if discoveryError}
      <div class="error-banner" role="alert">
        <strong>Discovery paused</strong>
        <span>{discoveryError}</span>
        {#if lastScan}<span>Last successful scan {lastScan}.</span>{/if}
      </div>
    {/if}

    <section class="devices" aria-label="Connected authenticators">
      {#if discoveryError}
        <div class="empty-state">
          <div class="empty-key" aria-hidden="true"></div>
          <h3>Discovery unavailable</h3>
          <p>
            The latest authenticator scan did not produce a trustworthy device
            snapshot. Fido Manager cleared the previous view until discovery
            succeeds again.
          </p>
          <span>Use Scan now to retry.</span>
        </div>
      {:else if snapshot && snapshot.devices.length > 0}
        <div class="device-grid">
          {#each snapshot.devices as device (device.handle)}
            <article class="device-card">
              <div class="device-card-head">
                <div class="key-icon" aria-hidden="true">
                  <div class="key-contact"></div>
                  <div class="key-body">
                    <span></span><span></span><span></span>
                  </div>
                </div>

                <div class="device-title">
                  <div class="status-line">
                    <span
                      class:ready={device.readStatus === 'ready'}
                      class="status-dot"
                    ></span>
                    <span>{friendlyStatus(device.readStatus)}</span>
                  </div>
                  <h3>{device.displayName}</h3>
                  {#if device.pinCheckPassed}
                    <span
                      class="verification-tag"
                      title="Historical PIN check only. Temporary authorization has been cleared."
                      >PIN check passed</span
                    >
                  {/if}
                  <p
                    title="Manufacturer and supported transports. Key numbers are temporary display labels."
                  >
                    {device.displayDetail}
                  </p>
                </div>

                <div class="vidpid">
                  <span>VID:PID</span>
                  <code>{hex16(device.vendorId)}:{hex16(device.productId)}</code
                  >
                </div>
              </div>

              <div
                class="chip-row"
                aria-label="Supported versions and transports"
              >
                {#each device.versions as version}
                  <span class="chip accent">{version}</span>
                {/each}
                {#each device.transports as transport}
                  <span class="chip">{transport.toUpperCase()}</span>
                {/each}
              </div>

              <div class="detail-grid">
                <div class="detail wide">
                  <span
                    title="Authenticator model/variant, not a unique physical key"
                    >AAGUID</span
                  >
                  <code>{device.aaguid ?? 'Not reported'}</code>
                </div>
                <div class="detail">
                  <span>Freshness</span>
                  <strong>{friendlyStatus(device.freshness)}</strong>
                </div>
                <div class="detail">
                  <span>Max message</span>
                  <strong>{device.maxMessageSize ?? '—'}</strong>
                </div>
                <div class="detail">
                  <span>Firmware</span>
                  <strong>{device.firmwareVersion ?? '—'}</strong>
                </div>
              </div>

              {#if device.extensions.length > 0 || device.options.length > 0}
                <div class="capability-block">
                  <span class="capability-label">CAPABILITIES</span>
                  <div class="capability-list">
                    {#each device.extensions as extension}
                      <span>{extension}</span>
                    {/each}
                    {#each device.options.filter((option) => option.enabled) as option}
                      <span>{option.name}</span>
                    {/each}
                  </div>
                </div>
              {/if}
            </article>
          {/each}
        </div>
      {:else if snapshot}
        <div class="empty-state">
          <div class="empty-key" aria-hidden="true"></div>
          <h3>No authenticator connected</h3>
          <p>
            Insert a USB FIDO2 security key. Fido Manager will detect it
            automatically.
          </p>
          <span>Scanning every second while this alpha is open.</span>
        </div>
      {:else}
        <div class="empty-state loading-state">
          <div class="scanner" aria-hidden="true"></div>
          <h3>Starting native discovery…</h3>
          <p>Establishing the local FIDO authority.</p>
        </div>
      {/if}
    </section>
    <section class="credential-inventory" aria-label="Credential inspection">
      <h2>Credentials</h2>
      {#if foundation?.inspection}
        {@const inventory = foundation.inspection}
        <p>Selected authenticator: {inventory.authenticator}</p>
        <p>
          <strong>{friendlyStatus(inventory.assessment.completeness)}</strong> ·
          {#if inventory.assessment.total.kind === 'exact'}Exact: {inventory
              .assessment.total.value}
          {:else if inventory.assessment.total.kind === 'at_least'}At least: {inventory
              .assessment.total.value}
          {:else}Unknown total{/if}
        </p>
        {#if inventory.assessment.completeness !== 'complete'}
          <p>
            Some entries could not be read or the authenticator returned
            conflicting data. This inventory does not establish an exact
            credential count.
          </p>
        {/if}
        {#if inventory.assessment.duplicate_rps}<p>
            Duplicate RP identities were preserved. Totals are unknown.
          </p>{/if}
        {#if inventory.assessment.duplicate_credentials}<p>
            Duplicate credential identities were returned. Totals are unknown.
          </p>{/if}
        {#each inventory.rps as rp}
          <article class="credential-rp">
            <h3>{rp.verifiedText ?? 'RP text unavailable or unverified'}</h3>
            {#if rp.issue}<p>
                Incomplete / unsupported: {friendlyStatus(rp.issue)}. An unread
                group is not an empty credential set.
              </p>{/if}
            <ul>
              {#each rp.credentials as credential (credential.handle)}
                <li>
                  {credential.displayName ?? credential.userName ?? 'Passkey'}
                  {#if credential.displayName && credential.userName}<span>
                      · {credential.userName}</span
                    >{/if}
                </li>
              {/each}
            </ul>
          </article>
        {/each}
        {#if inventory.assessment.completeness === 'complete' && inventory.rps.length === 0}<p
          >
            No resident credentials were reported.
          </p>{/if}
      {:else}
        <p>
          Choose “Inspect credentials” for a connected authenticator from the
          native Security key menu. Enter your PIN only in the native sheet.
        </p>
      {/if}
    </section>
  </main>

  <footer class="app-footer">
    <span>Fido Manager 0.1 alpha</span>
    <span class="footer-separator"></span>
    <span>{foundation?.phase ?? 'Milestone 1'}</span>
    <span class="footer-spacer"></span>
    <span>No secrets leave this device</span>
  </footer>
</div>

{#if noticeVisible && foundation?.authenticationNotice}
  <div class="authentication-toast" role="status" aria-live="polite">
    <div>
      <strong>Authentication result</strong>
      <p>{foundation.authenticationNotice}</p>
    </div>
    <button
      class="notice-dismiss"
      type="button"
      aria-label="Dismiss authentication result"
      onclick={dismissNotice}>Dismiss</button
    >
  </div>
{/if}
