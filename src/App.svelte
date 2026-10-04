<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { onMount } from 'svelte';
  import CredentialInventory from './CredentialInventory.svelte';
  import type {
    DeviceActivity,
    InspectionActivity,
    InspectionDisplay,
  } from './inspection';
  import logoUrl from './assets/fidomanager-logo.png';

  type FoundationStatus = {
    phase: string;
    workerProtocolVersion: number;
    reviewedLibfido2Baseline: string;
    inspectionActivity: InspectionActivity;
  };

  // Readiness of the BooGooCypher service only; says nothing about local security keys.
  type BooGooCypherStatus = 'checking' | 'online' | 'offline';

  type AuthenticatorOption = {
    name: string;
    enabled: boolean;
  };

  type Authenticator = {
    inspection: InspectionDisplay;
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
  let boogoocypher: BooGooCypherStatus = 'checking';
  let boogoocypherTimer: ReturnType<typeof setTimeout> | null = null;
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
  // The backend caches the result (30 s) and owns every network request; this only re-reads it.
  const boogoocypherPollMs = 5000;

  // A brief confirmation (success) or a problem that has no card to attach to. Per-key progress
  // and per-key problems are shown in that key's card, never in a replacement view.
  function updateNotice(
    revision: string | null,
    tone: 'success' | 'problem' | null,
  ) {
    if (revision === activeNoticeRevision) return;
    activeNoticeRevision = revision;
    if (noticeTimer) clearTimeout(noticeTimer);
    noticeVisible = revision !== null;
    if (noticeVisible) {
      noticeTimer = setTimeout(
        () => {
          noticeVisible = false;
        },
        tone === 'success' ? 4_000 : 10_000,
      );
    }
  }

  function dismissNotice() {
    noticeVisible = false;
    if (noticeTimer) clearTimeout(noticeTimer);
  }

  $: notice = foundation?.inspectionActivity?.notice ?? null;
  $: updateNotice(notice?.revision ?? null, notice?.tone ?? null);

  function activityFor(
    handle: string,
    activity: InspectionActivity | undefined,
  ): DeviceActivity {
    if (activity?.device === handle && activity.phase) {
      return { state: activity.phase };
    }
    if (activity?.issue?.device === handle) {
      return { state: 'attention', message: activity.issue.message };
    }
    return { state: 'idle' };
  }

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

  async function loadBooGooCypher() {
    try {
      const status = await invoke<BooGooCypherStatus>('boogoocypher_status');
      boogoocypher =
        status === 'online' || status === 'offline' ? status : 'checking';
    } catch {
      boogoocypher = 'checking';
    } finally {
      if (!stopped) {
        boogoocypherTimer = setTimeout(
          () => void loadBooGooCypher(),
          boogoocypherPollMs,
        );
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
    void loadBooGooCypher();
    return () => {
      stopped = true;
      if (timer) clearTimeout(timer);
      if (foundationTimer) clearTimeout(foundationTimer);
      if (boogoocypherTimer) clearTimeout(boogoocypherTimer);
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
        <span
          class="status-item"
          title="Readiness status only. BooGooCypher does not protect or process PINs, credentials or security-key operations, and its status never affects them."
        >
          <i
            aria-hidden="true"
            class:neutral={boogoocypher !== 'online'}
            class:checking={boogoocypher === 'checking'}
          ></i>
          BooGooCypher
          <strong
            >{boogoocypher === 'checking' ? 'checking…' : boogoocypher}</strong
          >
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
              <CredentialInventory
                inspection={device.inspection}
                activity={activityFor(
                  device.handle,
                  foundation?.inspectionActivity,
                )}
              />
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
  </main>

  <footer class="app-footer">
    <span>Fido Manager 0.1 alpha</span>
    <span class="footer-separator"></span>
    <span>{foundation?.phase ?? 'Milestone 1'}</span>
    <span class="footer-spacer"></span>
    <span>No secrets leave this device</span>
  </footer>
</div>

{#if noticeVisible && notice}
  <div
    class="inspection-toast"
    class:problem={notice.tone === 'problem'}
    role="status"
    aria-live="polite"
  >
    <span class="toast-mark" aria-hidden="true"
      >{notice.tone === 'success' ? '✓' : '!'}</span
    >
    <p>{notice.message}</p>
    <button
      class="notice-dismiss"
      type="button"
      aria-label="Dismiss message"
      onclick={dismissNotice}>Dismiss</button
    >
  </div>
{/if}
