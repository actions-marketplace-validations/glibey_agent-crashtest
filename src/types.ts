export type Severity = 'critical' | 'high' | 'medium' | 'low';

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  detail: string;
  fix: string;
  file?: string;
}

export type Client = 'claude-code' | 'cursor' | 'claude-desktop' | 'vscode';

export interface McpServer {
  name: string;
  client: Client;
  file: string;
  command?: string;
  args: string[];
  url?: string;
  env: Record<string, string>;
}

export interface SettingsFile {
  file: string;
  data: Record<string, any>;
}

export interface TextFile {
  file: string;
  content: string;
}

export interface Context {
  dir: string;
  home: string;
  includeHome: boolean;
  claudeSettings: SettingsFile[];
  mcpServers: McpServer[];
  instructionFiles: TextFile[];
  secretFiles: string[];
  /** Variable names (never values) found in project .env files, keyed by file. */
  envKeys: Record<string, string[]>;
}
