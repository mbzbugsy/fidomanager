export type InspectionSnapshot = {
  deviceHandle: string;
  deviceGeneration: string;
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

export type InspectionDisplay =
  | { state: 'not_inspected' }
  | { state: 'inspected'; snapshot: InspectionSnapshot };

// Presentation-only activity of the native credential inspection (fixed backend wording).
export type InspectionActivity = {
  device: string | null;
  generation: string | null;
  phase: 'waiting_for_pin' | 'reading_credentials' | null;
  issue: { device: string; generation: string; message: string } | null;
  notice: {
    revision: string;
    tone: 'success' | 'problem';
    message: string;
  } | null;
};

export type DeviceActivity =
  | { state: 'idle' }
  | { state: 'waiting_for_pin' }
  | { state: 'reading_credentials' }
  | { state: 'attention'; message: string };
