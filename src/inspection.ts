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
