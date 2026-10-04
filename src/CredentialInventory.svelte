<script lang="ts">
  import type { InspectionDisplay, InspectionSnapshot } from './inspection';
  export let inspection: InspectionDisplay;

  type Assessment = InspectionSnapshot['assessment'];

  function friendlyStatus(status: string) {
    return status.replace(/_/g, ' ');
  }
  function countLabel(value: number) {
    return `${value} ${value === 1 ? 'credential' : 'credentials'}`;
  }
  // Presentation only: the backend Complete/Incomplete/Inconsistent assessment and its
  // Exact/AtLeast/Unknown total are unchanged and never shown as enum words.
  function inventorySummary(assessment: Assessment) {
    const { total } = assessment;
    if (total.kind === 'exact') return countLabel(total.value ?? 0);
    if (total.kind === 'at_least')
      return `At least ${countLabel(total.value ?? 0)}`;
    return 'Credential count unavailable';
  }
  function inventoryWarning(assessment: Assessment) {
    const { total } = assessment;
    if (total.kind === 'at_least')
      return 'Some credentials could not be read. The actual total may be higher.';
    if (total.kind === 'unknown')
      return 'The authenticator returned conflicting inventory information.';
    return null;
  }
  // One primary label and an optional subdued secondary label. Never an ID or opaque handle.
  function credentialLabels(credential: {
    userName: string | null;
    displayName: string | null;
  }) {
    const display = credential.displayName?.trim()
      ? credential.displayName
      : null;
    const user = credential.userName?.trim() ? credential.userName : null;
    if (display && user && display !== user) {
      return { primary: display, secondary: user };
    }
    return { primary: display ?? user ?? 'Passkey', secondary: null };
  }
</script>

<section class="credential-section" aria-label="Credential inspection">
  {#if inspection.state === 'inspected'}
    {@const inventory = inspection.snapshot}
    {@const warning = inventoryWarning(inventory.assessment)}
    <div class="credential-head">
      <h4 class="credential-label">Credentials</h4>
      <strong class="credential-total" class:caution={warning !== null}
        >{inventorySummary(inventory.assessment)}</strong
      >
    </div>
    {#if warning}
      <p class="credential-note caution">
        <span aria-hidden="true">!</span>{warning}
      </p>
    {:else if inventory.assessment.completeness === 'complete'}
      <p class="credential-note quiet">Inventory complete</p>
    {/if}
    {#if inventory.assessment.duplicate_rps}<p class="credential-note caution">
        Duplicate RP identities were preserved. Totals are unknown.
      </p>{/if}
    {#if inventory.assessment.duplicate_credentials}<p
        class="credential-note caution"
      >
        Duplicate credential identities were returned. Totals are unknown.
      </p>{/if}
    {#if inventory.rps.length > 0}
      <ul class="credential-rps">
        {#each inventory.rps as rp}
          <li class="credential-rp">
            <div class="credential-rp-head">
              <h5>{rp.verifiedText ?? 'RP identity unavailable'}</h5>
              {#if rp.verifiedText !== null && !rp.issue}
                <span>{countLabel(rp.credentials.length)}</span>
              {:else}
                <span class="caution">Incomplete</span>
              {/if}
            </div>
            {#if rp.issue}<p class="credential-note caution">
                Could not be read ({friendlyStatus(rp.issue)}). An unread group
                is not an empty credential set.
              </p>{/if}
            {#if rp.credentials.length > 0}
              <ul class="credential-list">
                {#each rp.credentials as credential (credential.handle)}
                  {@const labels = credentialLabels(credential)}
                  <li>
                    <svg viewBox="0 0 24 24" aria-hidden="true">
                      <circle cx="8" cy="12" r="3.5" />
                      <path d="M11.5 12H21M17 12v3M20 12v2" />
                    </svg>
                    <span class="credential-name">{labels.primary}</span>
                    {#if labels.secondary}<span class="credential-sub"
                        >{labels.secondary}</span
                      >{/if}
                  </li>
                {/each}
              </ul>
            {/if}
          </li>
        {/each}
      </ul>
    {:else if inventory.assessment.completeness === 'complete'}
      <p class="credential-note">No resident credentials were reported.</p>
    {/if}
  {:else}
    <div class="credential-head">
      <h4 class="credential-label">Credentials</h4>
      <strong class="credential-total muted">Not inspected</strong>
    </div>
    <p class="credential-note">
      Inspection is started from the native Security key menu. Enter your PIN
      only in the native sheet.
    </p>
  {/if}
</section>
