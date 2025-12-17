
import React, { useState, useEffect, useRef } from 'react';
import { TerminalOutput } from './components/TerminalOutput';
import { analyzePduVulnerability, decodePdu, getGeneralEducationalInfo, getStkCommandInfo, simulateExfiltratedData, importStkParamsFromPdu } from './services/geminiService';
import { AnalysisResult, DecodedPdu, HistoryItem, StkCommand, StkBuilderParams } from './types';

const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'analyzer' | 'stk' | 'termux'>('analyzer');
  const [pduInput, setPduInput] = useState('');
  const [importPdu, setImportPdu] = useState('');
  
  // STK Builder State
  const [stkType, setStkType] = useState<'SAT_BROWSER' | 'PROACTIVE_SIM' | 'WIB'>('SAT_BROWSER');
  const [builderParams, setBuilderParams] = useState<StkBuilderParams>({
    commandType: 'DISPLAY TEXT',
    displayText: '',
    targetNumber: '',
    urlOrData: '',
    pinOrPassword: ''
  });

  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [isRunning, setIsRunning] = useState(false);
  const [currentAnalysis, setCurrentAnalysis] = useState<AnalysisResult | null>(null);
  const [decodedPdu, setDecodedPdu] = useState<DecodedPdu | null>(null);
  const [stkCommand, setStkCommand] = useState<StkCommand | null>(null);
  const [educationalContent, setEducationalContent] = useState<string>('');
  
  const scrollRef = useRef<HTMLDivElement>(null);
  const intervalRef = useRef<number | null>(null);
  const autoCommands = ['Get Location', 'Exfiltrate IMEI', 'Request Subscriber ID', 'Query Cell ID'];

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [history, currentAnalysis, stkCommand]);

  useEffect(() => {
    return () => {
      if (intervalRef.current) window.clearInterval(intervalRef.current);
    };
  }, []);

  const addLog = (content: string, type: HistoryItem['type'] = 'SYS_LOG') => {
    setHistory(prev => [...prev, {
      id: Math.random().toString(36).substr(2, 9),
      timestamp: Date.now(),
      type,
      content
    }]);
  };

  const educationalExamples = [
    {
      name: "Non-Root Setup Guide",
      type: "termux",
      description: "How to configure Termux for SMS research without requiring root access.",
      content: "Termux Setup (Non-Root):\n1. Install Termux:API app from F-Droid.\n2. Run: pkg install termux-api\n3. Grant SMS permissions in Android settings for Termux:API.\n4. Use: termux-sms-send -n [num] [msg]\n\nThis method uses the Android OS layer to send binary payloads, which is safer and doesn't risk bricking your baseband via direct root AT command access."
    },
    {
      name: "Silent SMS (Type 0)",
      type: "analyzer",
      pdu: "079144775810065011000A81100000000040",
      description: "A network ping that doesn't show up on the recipient's UI but returns a delivery receipt."
    },
    {
      name: "Simjacker Location",
      type: "stk",
      params: { commandType: "PROVIDE LOCAL INFO", displayText: "Get Location", urlOrData: "MCC/MNC/LAC/CellID" },
      stk: "SAT_BROWSER",
      description: "Classic S@T Browser vulnerability used to silently exfiltrate cell location data."
    },
    {
      name: "WIB IMEI Audit",
      type: "stk",
      params: { commandType: "DISPLAY TEXT", displayText: "Audit Mode", urlOrData: "IMEI_REQ" },
      stk: "WIB",
      description: "Targets the SmartTrust WIB applet to request hardware identifiers."
    }
  ];

  const applyExample = (ex: any) => {
    if (ex.type === 'analyzer' && ex.pdu) {
      setActiveTab('analyzer');
      setPduInput(ex.pdu);
      addLog(`[EXAMPLE] Loaded ${ex.name} into Analyzer.`, 'SYS_LOG');
    } else if (ex.type === 'stk' && ex.params) {
      setActiveTab('stk');
      setStkType(ex.stk as any);
      setBuilderParams({
        ...builderParams,
        ...ex.params
      });
      addLog(`[EXAMPLE] Loaded ${ex.name} into STK Builder.`, 'SYS_LOG');
    } else if (ex.type === 'termux') {
      setActiveTab('termux');
      setEducationalContent(ex.content);
      addLog(`[INFO] Displaying Non-Root configuration guide.`, 'SYS_LOG');
    }
  };

  const handleAnalysis = async () => {
    if (!pduInput.trim()) return;
    setIsAnalyzing(true);
    setDecodedPdu(null);
    setCurrentAnalysis(null);
    
    addLog(`pkg install sms-utils && python3 pdu_parse.py --hex ${pduInput.substring(0, 10)}...`, 'TERMUX_CMD');
    addLog(`[ANALYZING] Probing for protocol anomalies...`, 'VULN_SCAN');

    try {
      const [vulnResult, decodeResult] = await Promise.all([
        analyzePduVulnerability(pduInput),
        decodePdu(pduInput)
      ]);

      setCurrentAnalysis(vulnResult);
      setDecodedPdu(decodeResult);
      
      addLog(`Scan complete. Risk: ${vulnResult.riskLevel}.`, 'VULN_SCAN');
      if (vulnResult.isStkCommand) {
        addLog(`DETECTED: Binary SMS targeting ${vulnResult.targetApp || 'SIM Application'}.`, 'SYS_LOG');
      }
      addLog(`[DECODED] Bitstream parsed into ${decodeResult.components.length} components.`, 'SUCCESS');
    } catch (error) {
      addLog(`ERR: Analysis failed.`, 'SYS_LOG');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleImportPdu = async () => {
    if (!importPdu.trim()) return;
    setIsAnalyzing(true);
    addLog(`[STK] Importing parameters from existing PDU hex...`, 'SYS_LOG');
    try {
      const result = await importStkParamsFromPdu(importPdu);
      setStkType(result.stkType as any);
      setBuilderParams(prev => ({
        ...prev,
        ...result.params
      }));
      addLog(`[STK] Form pre-filled from PDU data.`, 'SUCCESS');
    } catch (error) {
      addLog(`[ERR] Failed to parse PDU for builder.`, 'SYS_LOG');
    } finally {
      setIsAnalyzing(false);
      setImportPdu('');
    }
  };

  const handleExecuteCommand = async (cmdType: string, isAuto: boolean = false, params?: StkBuilderParams) => {
    setIsAnalyzing(true);
    if (!isAuto) addLog(`termux-sms-send -b -n [TARGET] "STK_PAYLOAD_GEN"`, 'TERMUX_CMD');
    addLog(`Generating invisible ${stkType} ${params?.commandType || 'EXECUTE'} COMMAND...`, 'SYS_LOG');
    
    try {
      const info = await getStkCommandInfo(cmdType, stkType, params);
      setStkCommand(info);
      addLog(`STK payload ready: ${info.name}`, 'STK_GEN');
      
      if (isRunning || (!isAuto && !params)) {
        setTimeout(async () => {
          addLog(`[INTERCEPT] Incoming silent recovery SMS from target...`, 'SYS_LOG');
          const mockData = await simulateExfiltratedData(cmdType);
          addLog(`RECOVERY_DATA: ${mockData}`, 'RECV_DATA');
          addLog(`[SYSTEM] Information exfiltrated back via silent SMS.`, 'SUCCESS');
        }, 2500);
      }
    } catch (error) {
      addLog(`Command generation failed for ${cmdType}.`, 'SYS_LOG');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleBuilderSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const intent = `Construct a ${builderParams.commandType} command with text "${builderParams.displayText}", target "${builderParams.targetNumber}", data "${builderParams.urlOrData}", and pin "${builderParams.pinOrPassword}"`;
    handleExecuteCommand(intent, false, builderParams);
  };

  const toggleSimulation = () => {
    if (isRunning) stopSimulation();
    else startSimulation();
  };

  const startSimulation = () => {
    setIsRunning(true);
    addLog(`sh start_extensive_audit.sh`, 'TERMUX_CMD');
    addLog(`[SYSTEM] Starting automated vulnerability research sequence (Non-Root)...`, 'SYS_LOG');
    
    let index = 0;
    const runNext = () => {
      if (index >= autoCommands.length) {
        addLog(`[SYSTEM] Extensive audit sequence completed.`, 'SUCCESS');
        stopSimulation();
        return;
      }
      handleExecuteCommand(autoCommands[index], true);
      index++;
    };

    runNext();
    intervalRef.current = window.setInterval(runNext, 8000); 
  };

  const stopSimulation = () => {
    setIsRunning(false);
    if (intervalRef.current) {
      window.clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
    addLog(`[SYSTEM] Simulation halted by operator.`, 'SYS_LOG');
  };

  const fetchEducation = async (topic: string) => {
    setIsAnalyzing(true);
    addLog(`[INFO] Retrieving educational data for: ${topic}`, 'SYS_LOG');
    try {
      const info = await getGeneralEducationalInfo(topic);
      setEducationalContent(info);
    } catch (error) {
      addLog(`[ERR] Failed to fetch education module.`, 'SYS_LOG');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const clearHistory = () => {
    setHistory([]);
    setCurrentAnalysis(null);
    setDecodedPdu(null);
    setStkCommand(null);
    setPduInput('');
    setEducationalContent('');
    if (isRunning) stopSimulation();
  };

  return (
    <div className="min-h-screen bg-[#0a0a0a] text-emerald-500 p-4 md:p-8 flex flex-col gap-6 selection:bg-emerald-900 font-['Fira_Code']">
      <header className="border-b border-emerald-900/30 pb-4 flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div className="flex items-center gap-4">
          <div className="relative">
            <div className={`w-4 h-4 rounded-full ${isRunning ? 'bg-red-500 animate-ping' : 'bg-emerald-500'}`}></div>
            {isRunning && <div className="absolute top-0 left-0 w-4 h-4 rounded-full bg-red-500 opacity-75"></div>}
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
              SIM-SEC <span className="text-emerald-500">LAB</span>
            </h1>
            <p className="text-emerald-700 text-sm mt-1">SIM Vulnerability & STK Research Tool (Non-Root Ready)</p>
          </div>
        </div>
        
        <div className="flex flex-wrap items-center gap-3">
          <button 
            onClick={toggleSimulation}
            className={`px-4 py-1.5 rounded text-xs uppercase font-bold transition-all flex items-center gap-2 border ${
              isRunning 
                ? 'bg-red-600/20 text-red-500 border-red-500 hover:bg-red-600 hover:text-white' 
                : 'bg-emerald-600 text-black border-emerald-600 hover:bg-emerald-500 shadow-[0_0_10px_rgba(16,185,129,0.3)]'
            }`}
          >
            {isRunning ? (
              <><span className="w-1.5 h-1.5 bg-red-500 rounded-full animate-pulse"></span> STOP TEST</>
            ) : (
              <><span className="w-0 h-0 border-t-[4px] border-t-transparent border-l-[7px] border-l-black border-b-[4px] border-b-transparent"></span> START TEST</>
            )}
          </button>
          
          <div className="flex bg-[#111] p-1 rounded-lg border border-emerald-900/30">
            {(['analyzer', 'stk', 'termux'] as const).map(tab => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`px-4 py-1.5 rounded text-xs uppercase font-bold transition ${
                  activeTab === tab ? 'bg-emerald-600 text-black' : 'text-emerald-700 hover:text-emerald-400'
                }`}
              >
                {tab}
              </button>
            ))}
          </div>
        </div>
      </header>

      <main className="grid grid-cols-1 lg:grid-cols-12 gap-6 flex-grow">
        <div className="lg:col-span-8 flex flex-col gap-4">
          <div className="bg-[#0c0c0c] border border-emerald-900/30 rounded-lg terminal-glow flex-grow flex flex-col overflow-hidden h-[500px]">
            <div className="bg-emerald-950/20 px-4 py-2 border-b border-emerald-900/30 flex justify-between items-center">
              <span className="text-[10px] uppercase tracking-widest text-emerald-700 font-bold flex items-center gap-2">
                {isRunning && <span className="animate-pulse text-red-500">● LIVE_AUDIT_ACTIVE</span>}
                {activeTab === 'termux' ? '~/termux_lab' : 'SMS_PROTOCOL_LOGGER'}
              </span>
              <button onClick={clearHistory} className="text-[10px] text-red-900 hover:text-red-500 uppercase">Reset_Session</button>
            </div>
            
            <div ref={scrollRef} className="p-4 overflow-y-auto flex-grow font-mono text-xs md:text-sm space-y-1">
              {history.length === 0 && (
                <div className="h-full flex flex-col items-center justify-center text-center p-8 opacity-40">
                  <div className="text-4xl mb-4">🛡️</div>
                  <h3 className="text-lg font-bold mb-2">Non-Root Lab Ready</h3>
                  <p className="max-w-md text-sm">Select an example or a setup guide to begin research without root permissions.</p>
                </div>
              )}
              {history.map(item => (
                <TerminalOutput 
                  key={item.id} 
                  content={item.content} 
                  prefix={item.type === 'TERMUX_CMD' ? 'termux @ sim-lab: ~ $' : (item.type === 'RECV_DATA' ? '<<< [RECV]' : '$')}
                  type={
                    item.type === 'TERMUX_CMD' ? 'cmd' : 
                    item.type === 'SUCCESS' ? 'success' : 
                    item.type === 'RECV_DATA' ? 'warn' :
                    (item.content.includes('ALERT') || item.content.includes('WARNING') || item.content.includes('DETECTED') ? 'warn' : 'info')
                  } 
                />
              ))}
              {isAnalyzing && (
                <div className="flex items-center gap-2 text-emerald-400 italic py-1">
                  <span className="animate-bounce">>></span> Processing request...
                </div>
              )}
            </div>

            <div className="p-4 border-t border-emerald-900/30 bg-emerald-950/5">
              {activeTab === 'analyzer' && (
                <div className="flex flex-col gap-3">
                  <div className="flex gap-2">
                    <span className="text-emerald-700 font-bold">SCAN_HEX:</span>
                    <input 
                      className="bg-transparent border-none outline-none flex-grow text-white"
                      placeholder="Enter PDU hex..."
                      value={pduInput}
                      onChange={e => setPduInput(e.target.value)}
                      onKeyDown={e => e.key === 'Enter' && handleAnalysis()}
                    />
                    <button onClick={handleAnalysis} className="px-3 py-1 bg-emerald-600 text-black font-bold rounded">EXEC</button>
                  </div>
                  
                  {decodedPdu && (
                    <div className="mt-2 animate-in fade-in slide-in-from-top-2 duration-500">
                      <div className="text-[10px] text-emerald-700 font-bold uppercase mb-2 border-b border-emerald-900/30 pb-1">
                        PDU Bitstream Components
                      </div>
                      <div className="overflow-x-auto max-h-[150px]">
                        <table className="w-full text-[10px] border-collapse">
                          <thead>
                            <tr className="text-emerald-800 text-left border-b border-emerald-900/20">
                              <th className="py-1 pr-2">COMPONENT</th>
                              <th className="py-1 pr-2">HEX_VALUE</th>
                              <th className="py-1">DESCRIPTION</th>
                            </tr>
                          </thead>
                          <tbody>
                            {decodedPdu.components.map((comp, idx) => (
                              <tr key={idx} className={`border-b border-emerald-900/10 hover:bg-emerald-900/5 ${comp.isVulnerable ? 'text-red-400 font-bold shadow-[inset_2px_0_0_#f87171]' : ''}`}>
                                <td className="py-1 pr-2 align-top whitespace-nowrap">{comp.name}</td>
                                <td className="py-1 pr-2 align-top break-all font-bold">{comp.value}</td>
                                <td className="py-1 align-top opacity-80 leading-tight">{comp.description}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}
                </div>
              )}
              {activeTab === 'stk' && (
                <div className="flex flex-col gap-4">
                  <div className="flex gap-2 p-2 bg-emerald-950/10 border border-emerald-900/20 rounded">
                    <span className="text-[9px] font-bold text-emerald-700 uppercase pt-1">IMPORT PDU:</span>
                    <input 
                      className="bg-transparent border-none outline-none flex-grow text-[10px] text-emerald-400"
                      placeholder="Paste existing STK PDU hex to pre-fill form..."
                      value={importPdu}
                      onChange={e => setImportPdu(e.target.value)}
                    />
                    <button onClick={handleImportPdu} className="px-2 py-0.5 bg-emerald-900/30 hover:bg-emerald-900/60 rounded text-[9px] font-bold uppercase border border-emerald-800/50">MAP</button>
                  </div>

                  <form onSubmit={handleBuilderSubmit} className="bg-[#111]/50 p-3 rounded border border-emerald-900/20 grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div className="col-span-2 md:col-span-1 flex flex-col gap-1">
                      <label className="text-[9px] uppercase font-bold text-emerald-600">Environment</label>
                      <select 
                        className="bg-black border border-emerald-900/50 rounded px-2 py-1.5 text-[10px] text-white outline-none focus:border-emerald-500 transition-colors"
                        value={stkType}
                        onChange={e => setStkType(e.target.value as any)}
                      >
                        <option value="SAT_BROWSER">SAT BROWSER</option>
                        <option value="PROACTIVE_SIM">PROACTIVE SIM</option>
                        <option value="WIB">WIB</option>
                      </select>
                    </div>
                    <div className="col-span-2 md:col-span-1 flex flex-col gap-1">
                      <label className="text-[9px] uppercase font-bold text-emerald-600">Command</label>
                      <select 
                        className="bg-black border border-emerald-900/50 rounded px-2 py-1.5 text-[10px] text-white outline-none focus:border-emerald-500 transition-colors"
                        value={builderParams.commandType}
                        onChange={e => setBuilderParams({...builderParams, commandType: e.target.value})}
                      >
                        <option value="DISPLAY TEXT">DISPLAY TEXT</option>
                        <option value="SEND SMS">SEND SMS</option>
                        <option value="LAUNCH BROWSER">LAUNCH BROWSER</option>
                        <option value="SETUP CALL">SETUP CALL</option>
                        <option value="PROVIDE LOCAL INFO">LOCAL INFO</option>
                      </select>
                    </div>
                    <div className="col-span-2 md:col-span-2 flex flex-col gap-1">
                      <label className="text-[9px] uppercase font-bold text-emerald-600">Display / Info Text</label>
                      <input 
                        className="bg-black border border-emerald-900/50 rounded px-2 py-1.5 text-[10px] text-white outline-none focus:border-emerald-500 transition-colors"
                        placeholder="e.g. SIM Warning: Wallet Expired"
                        value={builderParams.displayText}
                        onChange={e => setBuilderParams({...builderParams, displayText: e.target.value})}
                      />
                    </div>
                    <div className="col-span-1 flex flex-col gap-1">
                      <label className="text-[9px] uppercase font-bold text-emerald-600">Test Recipient #</label>
                      <input 
                        className="bg-black border border-emerald-900/50 rounded px-2 py-1.5 text-[10px] text-white outline-none focus:border-emerald-500 transition-colors"
                        placeholder="Volunteered #"
                        value={builderParams.targetNumber}
                        onChange={e => setBuilderParams({...builderParams, targetNumber: e.target.value})}
                      />
                    </div>
                    <div className="col-span-1 flex flex-col gap-1">
                      <label className="text-[9px] uppercase font-bold text-emerald-600">PIN / PIN2</label>
                      <input 
                        className="bg-black border border-emerald-900/50 rounded px-2 py-1.5 text-[10px] text-white outline-none focus:border-emerald-500 transition-colors"
                        placeholder="0000"
                        value={builderParams.pinOrPassword}
                        onChange={e => setBuilderParams({...builderParams, pinOrPassword: e.target.value})}
                      />
                    </div>
                    <div className="col-span-2 flex flex-col gap-1">
                      <label className="text-[9px] uppercase font-bold text-emerald-600">URL / Asset Data</label>
                      <input 
                        className="bg-black border border-emerald-900/50 rounded px-2 py-1.5 text-[10px] text-white outline-none focus:border-emerald-500 transition-colors"
                        placeholder="e.g. http://evil.com or 16-digit-ID"
                        value={builderParams.urlOrData}
                        onChange={e => setBuilderParams({...builderParams, urlOrData: e.target.value})}
                      />
                    </div>
                    <div className="col-span-full pt-1">
                      <button 
                        type="submit"
                        className="w-full bg-emerald-600 text-black py-2 rounded text-[10px] font-bold uppercase hover:bg-emerald-500 transition-all flex items-center justify-center gap-2"
                      >
                        <span className="text-lg leading-none mt-[-2px]">+</span> GENERATE INTERACTIVE SMS APplet
                      </button>
                    </div>
                  </form>
                </div>
              )}
              {activeTab === 'termux' && (
                <div className="flex gap-2">
                  <span className="text-emerald-700 font-bold">$</span>
                  <input 
                    className="bg-transparent border-none outline-none flex-grow text-white"
                    placeholder="run educational script..."
                    onKeyDown={e => {
                      if (e.key === 'Enter') {
                        addLog((e.target as HTMLInputElement).value, 'TERMUX_CMD');
                        (e.target as HTMLInputElement).value = '';
                      }
                    }}
                  />
                </div>
              )}
            </div>
          </div>
        </div>

        <div className="lg:col-span-4 flex flex-col gap-4">
          <div className="bg-[#0c0c0c] border border-emerald-900/30 rounded-lg p-5">
            <h2 className="text-sm font-bold text-white border-b border-emerald-900/50 pb-2 flex items-center gap-2 uppercase tracking-tight">
              <span className="w-2 h-2 bg-blue-500 rounded-full"></span>
              Functional Examples
            </h2>
            <div className="mt-4 grid grid-cols-1 gap-2">
              {educationalExamples.map((ex, i) => (
                <button
                  key={i}
                  onClick={() => applyExample(ex)}
                  className="group text-left p-3 rounded bg-emerald-950/5 border border-emerald-900/10 hover:border-emerald-500/50 transition-all"
                >
                  <div className="flex justify-between items-center mb-1">
                    <span className="text-[10px] font-bold text-emerald-500 uppercase tracking-widest">{ex.name}</span>
                    <span className="text-[8px] bg-emerald-900/30 px-1 rounded text-emerald-800 uppercase">{ex.type}</span>
                  </div>
                  <p className="text-[9px] text-emerald-700 leading-tight group-hover:text-emerald-300">{ex.description}</p>
                </button>
              ))}
            </div>
          </div>

          <div className="bg-[#0c0c0c] border border-emerald-900/30 rounded-lg p-5 flex-grow overflow-hidden flex flex-col">
            <h2 className="text-sm font-bold text-white border-b border-emerald-900/50 pb-2 flex items-center gap-2">
              <span className="w-2 h-2 bg-blue-500 rounded-full"></span>
              {stkCommand ? 'PAYLOAD DETAILS' : 'KNOWLEDGE BASE'}
            </h2>
            <div className="mt-4 space-y-4 overflow-y-auto pr-2 text-xs flex-grow">
              {stkCommand ? (
                <div className="space-y-4 animate-in fade-in duration-500">
                  <div className="p-3 bg-red-950/20 border border-red-900/30 rounded">
                    <div className="flex justify-between items-start mb-2">
                      <p className="text-red-400 font-bold uppercase text-[10px]">STK Binary Stream ({stkCommand.stkType})</p>
                      <span className="text-[8px] px-1 bg-red-900 text-white rounded">STK_SMS</span>
                    </div>
                    <code className="block break-all bg-black p-2 rounded text-red-300 mb-3 leading-tight border border-red-900/30 font-mono text-[11px]">
                      {stkCommand.payload}
                    </code>
                    <p className="text-emerald-400 text-[10px] leading-tight mb-3">{stkCommand.description}</p>
                    
                    <div className="space-y-3">
                      <div className="p-2 bg-black/50 rounded border border-emerald-900/20">
                        <p className="text-[9px] text-emerald-700 font-bold mb-1 uppercase tracking-tighter">Termux (Non-Root):</p>
                        <code className="text-[9px] break-all opacity-70 block bg-black/80 p-1">termux-sms-send -b -n [TARGET] "{stkCommand.payload}"</code>
                      </div>
                      
                      <div className="p-2 bg-black/50 rounded border border-blue-900/20">
                        <p className="text-[9px] text-blue-700 font-bold mb-1 uppercase tracking-tighter">WSL / nc:</p>
                        <code className="text-[9px] break-all opacity-70 block bg-black/80 p-1">python3 -c "import os; os.system('echo ${stkCommand.payload} | xxd -r -p | nc [IP] 23')"</code>
                      </div>

                      <div className="p-2 bg-black/50 rounded border border-purple-900/20">
                        <p className="text-[9px] text-purple-700 font-bold mb-1 uppercase tracking-tighter">Gammu CLI:</p>
                        <code className="text-[9px] break-all opacity-70 block bg-black/80 p-1">gammu sendsms EMS [TARGET] -texthex {stkCommand.payload}</code>
                      </div>
                    </div>
                  </div>
                  <div>
                    <p className="font-bold text-white uppercase text-[10px]">Vulnerability Context:</p>
                    <p className="text-emerald-700 italic leading-relaxed text-[10px]">{stkCommand.impact}</p>
                  </div>
                  <button onClick={() => setStkCommand(null)} className="text-emerald-600 underline text-[10px] uppercase font-bold">Close Applet</button>
                </div>
              ) : educationalContent ? (
                <div className="space-y-3 animate-in fade-in duration-300">
                  <p className="leading-relaxed whitespace-pre-wrap opacity-90">{educationalContent}</p>
                  <button onClick={() => setEducationalContent('')} className="text-emerald-600 underline font-bold uppercase tracking-widest text-[9px]">Return</button>
                </div>
              ) : currentAnalysis ? (
                <div className="space-y-3 animate-in fade-in duration-500">
                  <div className={`p-3 border rounded ${
                    currentAnalysis.riskLevel === 'Critical' ? 'bg-red-950/30 border-red-500 text-red-400' :
                    currentAnalysis.riskLevel === 'High' ? 'bg-orange-950/30 border-orange-500 text-orange-400' :
                    'bg-emerald-950/30 border-emerald-500 text-emerald-400'
                  }`}>
                    <p className="font-bold uppercase text-[10px] mb-1">Vuln Scan Result: {currentAnalysis.riskLevel}</p>
                    <p className="leading-relaxed">{currentAnalysis.explanation}</p>
                  </div>
                  <div>
                    <p className="font-bold text-white uppercase text-[10px]">Mitigation Strategy:</p>
                    <p className="text-emerald-700 italic leading-relaxed">{currentAnalysis.mitigation}</p>
                  </div>
                  <button onClick={() => setCurrentAnalysis(null)} className="text-emerald-600 underline font-bold uppercase tracking-widest text-[9px]">New Analysis</button>
                </div>
              ) : (
                <div className="flex flex-col gap-2">
                  <TopicButton title="What is Simjacker?" onClick={() => fetchEducation('Simjacker Vulnerability Summary')} />
                  <TopicButton title="S@T Browser Protocol" onClick={() => fetchEducation('S@T Browser SIM Alliance Protocol')} />
                  <TopicButton title="EXECUTE COMMAND Specs" onClick={() => fetchEducation('STK EXECUTE COMMAND proactive command structure')} />
                  <TopicButton title="Mitigation Strategies" onClick={() => fetchEducation('How to protect SIM cards from silent commands')} />
                  <TopicButton title="IMEI/IMSI Exfiltration" onClick={() => fetchEducation('How SIM cards exfiltrate device identifiers via SMS')} />
                </div>
              )}
            </div>
          </div>
          
          <div className="bg-red-950/5 border border-red-900/20 p-4 rounded text-[10px] text-red-900/80 leading-relaxed uppercase">
            Educational purposes only. All Termux commands use the non-root "termux-api" method for safety and accessibility.
          </div>
        </div>
      </main>

      <footer className="text-center text-[10px] text-emerald-900/50 uppercase mt-4 flex justify-between px-2">
        <span>[SYSTEM: {isRunning ? 'PROBING' : 'IDLE'}]</span>
        <span>&copy; {new Date().getFullYear()} SMS-SEC Awareness Framework</span>
        <span>NODE: TERMUX_01_USERSPACE</span>
      </footer>
    </div>
  );
};

const TopicButton: React.FC<{ title: string; onClick: () => void }> = ({ title, onClick }) => (
  <button 
    onClick={onClick}
    className="text-left w-full p-2.5 rounded bg-emerald-950/5 border border-emerald-900/10 hover:border-emerald-500/30 transition text-emerald-600 hover:text-emerald-400 hover:bg-emerald-900/10 group"
  >
    <span className="inline-block mr-2 text-emerald-900 group-hover:text-emerald-500">▶</span> {title}
  </button>
);

export default App;
