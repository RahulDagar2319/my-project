export enum FlagStatus {
  ACTIVE = 'ACTIVE',
  INACTIVE = 'INACTIVE',
  ARCHIVED = 'ARCHIVED',
}

export enum FlagType {
  BOOLEAN = 'BOOLEAN',
  MULTIVARIATE = 'MULTIVARIATE',
}

export enum Operator {
  EQUALS = 'EQUALS',
  NOT_EQUALS = 'NOT_EQUALS',
  IN = 'IN',
  NOT_IN = 'NOT_IN',
  GREATER_THAN = 'GREATER_THAN',
  LESS_THAN = 'LESS_THAN',
}

export interface TargetingRule {
  id: string;
  attribute: string; // e.g., 'userId', 'email', 'region', 'plan'
  operator: Operator;
  values: string[]; // e.g., ['123', '456'] or ['premium']
}

export interface Variation {
    id: string;
    value: string; // "red", "blue", "control"
    name: string; // "Red Button", "Blue Button", "Original"
    weight: number; // Percentage, 0-100
}

export interface EnvironmentConfig {
  enabled: boolean;
  rolloutPercentage: number;
  rules: TargetingRule[];
  fallthroughVariantId?: string; // For multivariate
  offVariantId?: string; // For boolean/multivariate when disabled
}

export interface NewFlagPayload {
  key: string;
  name: string;
  description: string;
  type: FlagType;
  tags: string[];
  owner: string;
}

export interface FeatureFlag {
  id: string;
  key: string;
  name: string;
  description: string;
  type: FlagType;
  status: FlagStatus;
  tags: string[];
  owner: string;
  variations: Variation[];
  environments: {
    development: EnvironmentConfig;
    staging: EnvironmentConfig;
    production: EnvironmentConfig;
  };
  createdAt: string;
  updatedAt: string;
}

export interface AuditLog {
  id: string;
  flagId: string;
  timestamp: string;
  user: string;
  action: string; // e.g., 'CREATE_FLAG', 'UPDATE_RULE', 'TOGGLE_FLAG'
  details: {
    before: Partial<FeatureFlag>;
    after: Partial<FeatureFlag>;
  };
}

export interface UserContext {
    [key: string]: string | number | boolean;
}

export type Environment = 'development' | 'staging' | 'production';

export interface User {
  id: string;
  email: string;
}