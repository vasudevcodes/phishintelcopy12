import { useState, useRef } from 'react';
import type { FC, ChangeEvent, DragEvent } from 'react';
import { UploadCloud, FileText, AlertCircle, Loader2, Shield } from 'lucide-react';
import type { EmailAnalysisResponse } from '../types/forensics';

interface UploadZoneProps {
  onAnalysisComplete: (data: EmailAnalysisResponse) => void;
  isLoading: boolean;
  setIsLoading: (loading: boolean) => void;
  errorMessage: string | null;
  setErrorMessage: (msg: string | null) => void;
}

export const UploadZone: FC<UploadZoneProps> = ({
  onAnalysisComplete,
  isLoading,
  setIsLoading,
  errorMessage,
  setErrorMessage,
}) => {
  const [isDragOver, setIsDragOver] = useState(false);
  const [uploadFileName, setUploadFileName] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const processFile = async (file: File) => {
    setErrorMessage(null);
    setUploadFileName(file.name);

    // 1. Client-side extension validation
    if (!file.name.toLowerCase().endsWith('.eml')) {
      setErrorMessage(`Invalid file format "${file.name}". Only RFC 5322 .eml files are accepted for forensic parsing.`);
      setUploadFileName(null);
      return;
    }

    // 2. Client-side size check (10 MB limit)
    const MAX_SIZE = 10 * 1024 * 1024;
    if (file.size > MAX_SIZE) {
      const sizeMB = (file.size / (1024 * 1024)).toFixed(2);
      setErrorMessage(`File exceeds 10 MB limit (${sizeMB} MB). Please select an email file under 10 MB.`);
      setUploadFileName(null);
      return;
    }

    if (file.size === 0) {
      setErrorMessage('The selected email file is empty (0 bytes).');
      setUploadFileName(null);
      return;
    }

    setIsLoading(true);

    try {
      const formData = new FormData();
      formData.append('file', file);

      const response = await fetch('/api/v1/email/analyze', {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        let errorDetail = `Analysis failed with status ${response.status}`;
        try {
          const errData = await response.json();
          if (errData && errData.detail) {
            errorDetail = errData.detail;
          }
        } catch {
          // Keep default message
        }
        setErrorMessage(errorDetail);
        return;
      }

      const data: EmailAnalysisResponse = await response.json();
      onAnalysisComplete(data);
    } catch (err: unknown) {
      setErrorMessage(
        err instanceof Error
          ? `Network error: ${err.message}. Ensure the PhishIntel backend is running on port 8000.`
          : 'An unexpected connection error occurred during analysis.'
      );
    } finally {
      setIsLoading(false);
    }
  };

  const handleDragOver = (e: DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(true);
  };

  const handleDragLeave = (e: DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
  };

  const handleDrop = (e: DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      processFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileSelect = (e: ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      processFile(e.target.files[0]);
      e.target.value = '';
    }
  };

  const openPicker = () => {
    if (!isLoading) fileInputRef.current?.click();
  };

  return (
    <div className="w-full">
      <div
        role="button"
        tabIndex={isLoading ? -1 : 0}
        aria-label="Upload an .eml file for analysis"
        aria-busy={isLoading}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={openPicker}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            openPicker();
          }
        }}
        className={`relative overflow-hidden rounded-2xl p-1.5 transition-all cursor-pointer bg-white shadow-card ${
          isDragOver ? 'shadow-ring-brand ring-2 ring-brand-500' : 'hover:shadow-card-hover'
        } ${isLoading ? 'pointer-events-none cursor-wait' : ''}`}
      >
        <input
          id="email-file-input"
          ref={fileInputRef}
          type="file"
          accept=".eml"
          onChange={handleFileSelect}
          className="hidden"
          disabled={isLoading}
        />

        {isLoading && (
          <div className="absolute top-0 left-0 right-0 h-0.5 bg-brand-100 overflow-hidden" aria-hidden="true">
            <div className="h-full w-1/4 bg-brand-500 animate-scan" />
          </div>
        )}

        <div
          className={`rounded-xl border border-dashed px-6 py-10 sm:py-14 text-center transition-colors ${
            isDragOver ? 'border-brand-500 bg-brand-50/60' : 'border-slate-300 bg-slate-50/50'
          }`}
        >
          <div className="flex flex-col items-center gap-5">
            <div
              className={`w-14 h-14 rounded-xl flex items-center justify-center bg-white ring-1 transition-transform ${
                isDragOver ? 'scale-110 ring-brand-300' : 'ring-slate-200 shadow-subtle'
              }`}
            >
              {isLoading ? (
                <Loader2 className="w-6 h-6 text-brand-600 animate-spin" />
              ) : (
                <UploadCloud className="w-6 h-6 text-brand-600" />
              )}
            </div>

            <div className="space-y-1.5 max-w-md mx-auto">
              <h3 className="text-lg font-semibold text-navy-900 tracking-tight">
                {isLoading
                  ? `Analyzing ${uploadFileName || 'email'}…`
                  : isDragOver
                    ? 'Release to begin analysis'
                    : 'Drop an email to investigate'}
              </h3>
              <p className="text-sm text-slate-500 leading-relaxed">
                {isLoading ? (
                  'Reconstructing transit hops, scoring text with DistilBERT and verifying signatures.'
                ) : (
                  <>
                    Drag a{' '}
                    <code className="font-mono text-xs px-1.5 py-0.5 rounded bg-white ring-1 ring-slate-200 text-navy-900 font-medium">
                      .eml
                    </code>{' '}
                    file here, or{' '}
                    <span className="text-brand-600 font-medium underline underline-offset-4 decoration-brand-300">
                      browse your computer
                    </span>
                  </>
                )}
              </p>
            </div>

            <ul className="flex flex-wrap items-center justify-center gap-2 text-xs text-slate-600">
              <li className="inline-flex items-center px-2.5 py-1 rounded-md bg-white ring-1 ring-slate-200">
                <FileText className="w-3.5 h-3.5 mr-1.5 text-slate-400" />
                RFC 5322 (.eml)
              </li>
              <li className="inline-flex items-center px-2.5 py-1 rounded-md bg-white ring-1 ring-slate-200">
                Up to 10 MB
              </li>
              <li className="inline-flex items-center px-2.5 py-1 rounded-md bg-emerald-50 ring-1 ring-emerald-200 text-emerald-800">
                <Shield className="w-3.5 h-3.5 mr-1.5 text-emerald-600" />
                Offline &amp; isolated
              </li>
            </ul>
          </div>
        </div>
      </div>

      {errorMessage && (
        <div
          role="alert"
          className="mt-4 p-4 rounded-xl bg-red-50 ring-1 ring-red-200 text-red-900 flex items-start gap-3 text-sm animate-fade-in"
        >
          <AlertCircle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" />
          <div className="flex-1">
            <span className="font-semibold text-red-800">Ingestion notice: </span>
            <span className="text-red-700">{errorMessage}</span>
          </div>
        </div>
      )}
    </div>
  );
};
