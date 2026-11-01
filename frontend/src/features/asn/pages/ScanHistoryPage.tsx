import React from 'react';
import { ScanHistoryItem } from '../../../types/asn';
import { HistoryTable } from '../components/HistoryTable';

interface ScanHistoryPageProps {
  history: ScanHistoryItem[];
  onSelectScan: (scanId: string) => void;
  onDeleteScan: (scanId: string) => void;
}

export const ScanHistoryPage: React.FC<ScanHistoryPageProps> = ({
  history,
  onSelectScan,
  onDeleteScan
}) => {
  return (
    <div className="space-y-6">
      <HistoryTable
        history={history}
        onSelectScan={onSelectScan}
        onDeleteScan={onDeleteScan}
      />
    </div>
  );
};
