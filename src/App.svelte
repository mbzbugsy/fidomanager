<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { onMount } from 'svelte';

  type FoundationStatus = {
    phase: string;
    workerProtocolVersion: number;
    reviewedLibfido2Baseline: string;
  };

  let status: FoundationStatus | null = null;
  let error: string | null = null;

  onMount(async () => {
    try {
      status = await invoke<FoundationStatus>('foundation_status');
    } catch {
      error = 'Unable to read native foundation status.';
    }
  });
</script>

<main>
  <section class="shell" aria-labelledby="title">
    <p class="eyebrow">Milestone 0</p>
    <h1 id="title">FidoManager</h1>
    <p class="lede">
      Vendor-neutral FIDO2 / CTAP authenticator management. Device access is
      intentionally disabled in this foundation build.
    </p>

    {#if status}
      <dl>
        <div>
          <dt>Phase</dt>
          <dd>{status.phase}</dd>
        </div>
        <div>
          <dt>Worker protocol</dt>
          <dd>v{status.workerProtocolVersion}</dd>
        </div>
        <div>
          <dt>Reviewed libfido2 baseline</dt>
          <dd>{status.reviewedLibfido2Baseline}</dd>
        </div>
      </dl>
    {:else if error}
      <p role="alert">{error}</p>
    {:else}
      <p>Loading native foundation status…</p>
    {/if}
  </section>
</main>
