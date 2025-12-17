
export interface PduComponent {
  name: string;
  value: string;
  description: string;
  isVulnerable?: boolean;
}

export interface DecodedPdu {
  components: PduComponent[];
}

export interface AnalysisResult {
  isSilent: boolean;
  explanation: string;
  riskLevel: 'Low' | 'Medium' | 'High' | 'Critical';
  mitigation: string;
  isStkCommand?: boolean;
  targetApp?: string;
}

export interface StkBuilderParams {
  displayText?: string;
  targetNumber?: string;
  urlOrData?: string;
  pinOrPassword?: string;
  commandType?: string;
}

export interface StkCommand {
  name: string;
  description: string;
  payload: string;
  impact: string;
  stkType?: 'SAT_BROWSER' | 'PROACTIVE_SIM' | 'WIB';
}

export interface HistoryItem {
  id: string;
  timestamp: number;
  type: 'PDU_ENCODE' | 'VULN_SCAN' | 'STK_GEN' | 'SYS_LOG' | 'TERMUX_CMD' | 'SUCCESS' | 'RECV_DATA';
  content: string;
}
