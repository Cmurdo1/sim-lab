
import React from 'react';

interface TerminalOutputProps {
  prefix?: string;
  content: string;
  type?: 'cmd' | 'info' | 'error' | 'success' | 'warn';
}

export const TerminalOutput: React.FC<TerminalOutputProps> = ({ 
  prefix = '$', 
  content, 
  type = 'info' 
}) => {
  const colorMap = {
    cmd: 'text-white',
    info: 'text-emerald-400',
    error: 'text-red-500',
    success: 'text-green-500',
    warn: 'text-yellow-400',
  };

  return (
    <div className="mb-2 break-all">
      <span className="mr-2 text-emerald-600 font-bold">{prefix}</span>
      <span className={`${colorMap[type]}`}>{content}</span>
    </div>
  );
};
