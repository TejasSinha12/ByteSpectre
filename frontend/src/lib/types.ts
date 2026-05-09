export type RiskLevel = 'LOW' | 'GUARDED' | 'ELEVATED' | 'CRITICAL';

export interface Indicator {
  id: string;
  title: string;
  category: string;
  severity: number;
  confidence: number;
  evidence: string;
  explanation: string;
}

export interface ArtifactClassification {
  id: string;
  label: string;
  family: string;
  confidence: number;
  evidence: string[];
  explanation: string;
}

export interface DescriptorMetadata {
  path: string;
  type: string;
  fields: Record<string, string>;
}

export interface PackageSummary {
  name: string;
  classCount: number;
  suspiciousSignalCount: number;
}

export interface ClassRelationship {
  source: string;
  target: string;
  type: string;
}

export interface MethodCallEdge {
  sourceClass: string;
  sourceMethod: string;
  targetOwner: string;
  targetMethod: string;
  descriptor: string;
}

export interface AssetFinding {
  path: string;
  type: string;
  signal: string;
  explanation: string;
}

export interface JarAnalysisReport {
  analysisId: string;
  fileName: string;
  fileSizeBytes: number;
  sha256: string;
  analyzedAt: string;
  riskLevel: RiskLevel;
  riskScore: number;
  summary: string;
  manifest: Record<string, string>;
  behaviorCategories: string[];
  artifactClassifications: ArtifactClassification[];
  descriptorMetadata: DescriptorMetadata[];
  channelFindings: {
    system: string;
    direction: string;
    channel: string;
    sourceClass: string;
    sourceMethod: string;
  }[];
  indicators: Indicator[];
  packages: PackageSummary[];
  relationships: ClassRelationship[];
  methodCallEdges: MethodCallEdge[];
  assetFindings: AssetFinding[];
  resourceSummary: Record<string, number>;
  aiSignals: Record<string, unknown>;
}

export interface AnalysisCapabilities {
  staticEngineVersion: string;
  artifactFamilies: string[];
  descriptorFormats: string[];
  detectorFamilies: string[];
  exportFormats: string[];
}
