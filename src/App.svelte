<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { onMount } from 'svelte';

  type FoundationStatus = {
    phase: string;
    workerProtocolVersion: number;
    reviewedLibfido2Baseline: string;
  };

  type AuthenticatorOption = {
    name: string;
    enabled: boolean;
  };

  type Authenticator = {
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

  const pollDelayMs = 1000;

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
    };
  });
</script>

<svelte:head>
  <title>FidoManager</title>
</svelte:head>

<div class="app-frame">
  <header class="topbar">
    <div class="brand" aria-label="FidoManager">
      <div class="brand-mark" aria-hidden="true">
        <img src="/fidomanager-logo.png" alt="" />
      </div>
      <div>
        <strong>FidoManager</strong>
        <small>Authenticator control</small>
      </div>
    </div>

    <div class="topbar-meta">
      <span class="privacy-pill"><i></i> Local only</span>
      <span class="mode-pill">Read-only alpha</span>
    </div>
  </header>

  <main class="workspace">
    <section class="intro" aria-labelledby="page-title">
      <div>
        <p class="eyebrow">FIDO2 / CTAP DEVICE MANAGER</p>
        <h1 id="page-title">
          Your security keys.<br />Visible and under control.
        </h1>
        <p class="lede">
          FidoManager talks directly to authenticators on this Mac. No account,
          no cloud, no telemetry.
        </p>
      </div>

      <button
        class="refresh-button"
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
    </section>

    <section class="system-strip" aria-label="Discovery status">
      <div class="system-item">
        <span class="system-label">Native service</span>
        <strong class:warning={Boolean(discoveryError)}
          >{discoveryError ? 'Attention' : 'Online'}</strong
        >
      </div>
      <div class="system-item">
        <span class="system-label">Discovery epoch</span>
        <strong>{snapshot?.enumerationEpoch ?? '—'}</strong>
      </div>
      <div class="system-item">
        <span class="system-label">Last scan</span>
        <strong>{lastScan ?? 'Starting…'}</strong>
      </div>
      <div class="system-item">
        <span class="system-label">libfido2</span>
        <strong>{foundation?.reviewedLibfido2Baseline ?? '—'}</strong>
      </div>
    </section>

    {#if discoveryError}
      <div class="error-banner" role="alert">
        <strong>Discovery paused</strong>
        <span>{discoveryError}</span>
      </div>
    {/if}

    <section class="devices" aria-labelledby="devices-title">
      <div class="section-heading">
        <div>
          <p class="section-kicker">CONNECTED HARDWARE</p>
          <h2 id="devices-title">Authenticators</h2>
        </div>
        <span class="device-count"
          >{snapshot?.devices.length ?? 0} detected</span
        >
      </div>

      {#if discoveryError}
        <div class="empty-state">
          <div class="empty-key" aria-hidden="true"></div>
          <h3>Discovery unavailable</h3>
          <p>
            The latest authenticator scan did not produce a trustworthy device
            snapshot. FidoManager cleared the previous view until discovery
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
                  <h3>{device.product ?? 'FIDO authenticator'}</h3>
                  <p>{device.manufacturer ?? 'Unknown manufacturer'}</p>
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
                  <span>AAGUID</span>
                  <code>{device.aaguid ?? 'Not reported'}</code>
                </div>
                <div class="detail">
                  <span>Generation</span>
                  <strong>{device.generation}</strong>
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

              <footer class="device-footer">
                <span>Handle</span>
                <code
                  >{device.handle.slice(0, 8)}…{device.handle.slice(-8)}</code
                >
              </footer>
            </article>
          {/each}
        </div>
      {:else if snapshot}
        <div class="empty-state">
          <div class="empty-key" aria-hidden="true"></div>
          <h3>No authenticator connected</h3>
          <p>
            Insert a USB FIDO2 security key. FidoManager will detect it
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
    <span>FidoManager 0.1 alpha</span>
    <span class="footer-separator"></span>
    <span>{foundation?.phase ?? 'Milestone 1'}</span>
    <span class="footer-spacer"></span>
    <span>No secrets leave this device</span>
  </footer>
</div>

<style>
  .brand-mark {
    overflow: hidden;
    border: 0;
    background: transparent;
  }

  .brand-mark::before,
  .brand-mark::after {
    display: none;
  }

  .brand-mark img {
    display: block;
    width: 100%;
    height: 100%;
    object-fit: contain;
  }
</style>
