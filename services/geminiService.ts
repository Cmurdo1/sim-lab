
import { GoogleGenAI, Type } from "@google/genai";
import { AnalysisResult, StkCommand, DecodedPdu, StkBuilderParams } from "../types";

// Helper to get fresh AI instance
const getAi = () => new GoogleGenAI({ apiKey: process.env.API_KEY });

export const analyzePduVulnerability = async (pdu: string): Promise<AnalysisResult> => {
  const ai = getAi();
  const response = await ai.models.generateContent({
    model: "gemini-3-pro-preview",
    contents: `Analyze this SMS PDU string for educational vulnerability awareness: "${pdu}". 
    Focus specifically on Protocol Identifier (PID), Data Coding Scheme (DCS), and User Data Header (UDH). 
    Check if it targets the SIM Toolkit (STK) or S@T Browser application (Simjacker type vulnerability).
    Determine if it is an EXECUTE COMMAND instruction.`,
    config: {
      responseMimeType: "application/json",
      responseSchema: {
        type: Type.OBJECT,
        properties: {
          isSilent: { type: Type.BOOLEAN },
          isStkCommand: { type: Type.BOOLEAN },
          targetApp: { type: Type.STRING },
          explanation: { type: Type.STRING },
          riskLevel: { 
            type: Type.STRING,
            enum: ['Low', 'Medium', 'High', 'Critical']
          },
          mitigation: { type: Type.STRING }
        },
        required: ["isSilent", "explanation", "riskLevel", "mitigation"]
      }
    }
  });

  try {
    return JSON.parse(response.text.trim());
  } catch (e) {
    return {
      isSilent: false,
      explanation: "Failed to parse analysis results.",
      riskLevel: "Low",
      mitigation: "Ensure the PDU string is valid hex format."
    };
  }
};

export const decodePdu = async (pdu: string): Promise<DecodedPdu> => {
  const ai = getAi();
  const response = await ai.models.generateContent({
    model: "gemini-3-flash-preview",
    contents: `Decode the following SMS PDU hex string into its protocol components: "${pdu}".
    Identify SMSC, PDU Type, OA/DA, PID, DCS, SCTS, UDL, and UD.
    For each component, provide:
    1. Name (e.g., "Data Coding Scheme")
    2. Value (The extracted hex or decoded value)
    3. Description (Educational explanation of what this field does)
    4. isVulnerable (Boolean: true if the value indicates a silent SMS, MWI, or binary/STK command manipulation)
    Return as JSON.`,
    config: {
      responseMimeType: "application/json",
      responseSchema: {
        type: Type.OBJECT,
        properties: {
          components: {
            type: Type.ARRAY,
            items: {
              type: Type.OBJECT,
              properties: {
                name: { type: Type.STRING },
                value: { type: Type.STRING },
                description: { type: Type.STRING },
                isVulnerable: { type: Type.BOOLEAN }
              },
              required: ["name", "value", "description"]
            }
          }
        },
        required: ["components"]
      }
    }
  });

  try {
    return JSON.parse(response.text.trim());
  } catch (e) {
    return { components: [] };
  }
};

export const importStkParamsFromPdu = async (pdu: string): Promise<{params: StkBuilderParams, stkType: string}> => {
  const ai = getAi();
  const response = await ai.models.generateContent({
    model: "gemini-3-flash-preview",
    contents: `Examine this SMS PDU: "${pdu}". 
    Extract values to pre-fill an STK command builder form. 
    Map fields like User Data to 'displayText', URLs to 'urlOrData', or specific numbers to 'targetNumber'.
    Identify the most likely 'stkType' (SAT_BROWSER, PROACTIVE_SIM, or WIB) based on the payload structure.
    Return as JSON.`,
    config: {
      responseMimeType: "application/json",
      responseSchema: {
        type: Type.OBJECT,
        properties: {
          stkType: { type: Type.STRING, enum: ['SAT_BROWSER', 'PROACTIVE_SIM', 'WIB'] },
          params: {
            type: Type.OBJECT,
            properties: {
              commandType: { type: Type.STRING },
              displayText: { type: Type.STRING },
              targetNumber: { type: Type.STRING },
              urlOrData: { type: Type.STRING },
              pinOrPassword: { type: Type.STRING }
            }
          }
        },
        required: ["stkType", "params"]
      }
    }
  });

  try {
    return JSON.parse(response.text.trim());
  } catch (e) {
    return { 
      stkType: 'SAT_BROWSER', 
      params: { commandType: 'DISPLAY TEXT', displayText: '', targetNumber: '', urlOrData: '', pinOrPassword: '' } 
    };
  }
};

export const getStkCommandInfo = async (commandName: string, stkType: string = 'SAT_BROWSER', params?: StkBuilderParams): Promise<StkCommand> => {
  const ai = getAi();
  const paramSummary = params ? `
  Parameters provided:
  - Command Type: ${params.commandType || 'N/A'}
  - Display Text: ${params.displayText || 'N/A'}
  - Target Number: ${params.targetNumber || 'N/A'}
  - URL/Data: ${params.urlOrData || 'N/A'}
  - PIN/Password: ${params.pinOrPassword || 'N/A'}
  ` : '';

  const response = await ai.models.generateContent({
    model: "gemini-3-pro-preview",
    contents: `Generate an educational example of a SIM Toolkit binary payload for the ${stkType} environment. 
    Command Intent: "${commandName}".
    ${paramSummary}
    
    The payload should be a hypothetical but technically accurate hex string representing a proactive command. 
    Explain how this can be sent in Termux using "termux-api" (termux-sms-send) WITHOUT requiring root access.
    
    Format the response as JSON.`,
    config: {
      responseMimeType: "application/json",
      responseSchema: {
        type: Type.OBJECT,
        properties: {
          name: { type: Type.STRING },
          description: { type: Type.STRING },
          payload: { type: Type.STRING },
          impact: { type: Type.STRING },
          stkType: { type: Type.STRING, enum: ['SAT_BROWSER', 'PROACTIVE_SIM', 'WIB'] }
        },
        required: ["name", "description", "payload", "impact", "stkType"]
      }
    }
  });
  return JSON.parse(response.text.trim());
};

export const simulateExfiltratedData = async (commandType: string): Promise<string> => {
  const ai = getAi();
  const response = await ai.models.generateContent({
    model: "gemini-3-flash-preview",
    contents: `Simulate a mock recovery SMS payload for a research lab. The SIM just executed "${commandType}". 
    Generate a JSON string containing mock device info (IMEI, location coords, or cell id) that looks like it was exfiltrated. 
    Wrap it in a technical-looking SMS delivery log format.`,
  });
  return response.text;
};

export const getGeneralEducationalInfo = async (topic: string): Promise<string> => {
  const ai = getAi();
  const response = await ai.models.generateContent({
    model: "gemini-3-flash-preview",
    contents: `You are an educational security researcher. Explain "${topic}" (specifically S@T Browser Execute Commands) in the context of mobile security. 
    Crucially, focus on how a non-root user in Termux can study these protocols using the "termux-api" package. 
    Explain the difference between direct modem access (Root) and high-level API access (Non-Root) for research.`,
  });
  return response.text;
};
