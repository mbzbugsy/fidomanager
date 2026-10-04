// Presentation only. The parameter-free backend command owns this classification.
export type DiscoveryResult<T> =
  | { state: 'fresh'; list: T }
  | { state: 'settling' }
  | { state: 'unavailable' };

export type DiscoveryView<T> = {
  state: 'starting' | 'fresh' | 'settling' | 'unavailable';
  list: T | null;
};

export function applyDiscovery<T>(
  previous: DiscoveryView<T>,
  result: DiscoveryResult<T>,
): DiscoveryView<T> {
  switch (result.state) {
    case 'fresh':
      return { state: 'fresh', list: result.list };
    case 'settling':
      return { state: 'settling', list: previous.list };
    default:
      return { state: 'unavailable', list: null };
  }
}
