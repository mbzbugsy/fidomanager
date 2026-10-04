<script lang="ts">
  import type { InspectionDisplay } from './inspection';
  export let inspection: InspectionDisplay;
  function friendlyStatus(status: string) {
    return status.replace(/_/g, ' ');
  }
</script>

<section class="credential-inventory" aria-label="Credential inspection">
  <h2>Credentials</h2>
  {#if inspection.state === 'inspected'}
    {@const inventory = inspection.snapshot}
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
        Some entries could not be read or the authenticator returned conflicting
        data. This inventory does not establish an exact credential count.
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
    <p><strong>Not inspected</strong></p>
    <p>
      Choose “Inspect credentials” for this authenticator from the native
      Security key menu. Enter your PIN only in the native sheet.
    </p>
  {/if}
</section>
