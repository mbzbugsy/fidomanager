// Presentation only. The parameter-free backend command owns this classification.
export type DiscoveryResult<T> =
  | { state: 'fresh'; list: T }
  | { state: 'settling' }
  | { state: 'unavailable' }
  | { state: 'integrity_failure' };

export type DiscoveryView<T> = {
  state:
    'starting' | 'fresh' | 'settling' | 'unavailable' | 'integrity_failure';
  list: T | null;
};

// Fixed, backend-classified category. The renderer receives no identity detail and offers no
// retry, override or verification-mode control for it.
export const INTEGRITY_FAILURE_MESSAGE =
  'Fido Manager could not verify its own components. Reinstall it from the official release.';

export function applyDiscovery<T>(
  previous: DiscoveryView<T>,
  result: DiscoveryResult<T>,
): DiscoveryView<T> {
  switch (result.state) {
    case 'fresh':
      return { state: 'fresh', list: result.list };
    case 'settling':
      return { state: 'settling', list: previous.list };
    case 'integrity_failure':
      return { state: 'integrity_failure', list: null };
    default:
      return { state: 'unavailable', list: null };
  }
}
