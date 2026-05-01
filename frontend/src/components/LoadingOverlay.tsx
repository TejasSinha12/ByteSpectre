export function LoadingOverlay() {
  return (
    <div className="loading-overlay" role="status" aria-live="polite">
      <div className="scan-spinner" />
      <strong>Analyzing artifact</strong>
      <span>Parsing bytecode, resources, descriptors, and detector signals.</span>
    </div>
  );
}

