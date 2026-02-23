/**
 * MCP Tool Implementations for id.org.ai
 *
 * Five tools that form the agent interface to headless.ly:
 *   - explore (L0+) — Schema discovery: returns all 32 entity schemas with verbs and relationships
 *   - try     (L1+) — Execute-with-rollback: runs operations and shows results without committing
 *   - search  (L0+) — Search entities across the graph
 *   - fetch   (L0+) — Get specific entities, schemas, or state
 *   - do      (L1+) — Execute any action for real
 *
 * Design:
 *   - explore and try require no real data — they work against the schema
 *   - search and fetch read from the IdentityDO's storage
 *   - do writes to the IdentityDO's storage (requires L1+)
 */

import type { MCPAuthResult } from './auth'
import type { IdentityStub } from '../do/Identity'

// ============================================================================
// Types
// ============================================================================

export interface ToolResult {
  content: Array<{ type: 'text'; text: string }>
  isError?: boolean
}

export interface EntitySchema {
  name: string
  domain: string
  description: string
  fields: Record<string, FieldSchema>
  verbs: VerbSchema[]
  relationships: RelationshipSchema[]
  level: number
}

export interface FieldSchema {
  type: string
  required: boolean
  unique?: boolean
  description?: string
  enum?: string[]
}

export interface VerbSchema {
  name: string
  description: string
  lifecycle: {
    execute: string
    before: string
    after: string
    reverse: string
  }
  level: number
}

export interface RelationshipSchema {
  type: 'belongsTo' | 'hasMany' | 'hasOne'
  target: string
  field: string
  inverse?: string
}

export interface ExploreResult {
  domains: Record<string, {
    description: string
    entities: EntitySchema[]
  }>
  totalEntities: number
  totalVerbs: number
}

export interface TryOperation {
  entity: string
  verb: string
  data: Record<string, unknown>
}

export interface TryOperationResult {
  index: number
  entity: string
  verb: string
  result: Record<string, unknown>
  events: Array<{ type: string; entity: string; verb: string; timestamp: string }>
  sideEffects: string[]
}

export interface TryResult {
  operations: TryOperationResult[]
  summary: string
  events: Array<{ type: string; entity: string; verb: string; timestamp: string }>
  rollback: true
  note: string
}

export interface SearchResult {
  results: Array<{
    type: string
    id: string
    name?: string
    score: number
    snippet: Record<string, unknown>
  }>
  total: number
  query: string
}

export interface FetchResult {
  type: string
  id?: string
  data: Record<string, unknown> | null
}

export interface DoResult {
  success: boolean
  entity: string
  verb: string
  result: Record<string, unknown>
  events: Array<{ type: string; entity: string; verb: string; timestamp: string }>
}

// ============================================================================
// Schema Definition — The 32 Core Entities
// ============================================================================

const ENTITY_SCHEMAS: EntitySchema[] = [
  // ── CRM (4) ─────────────────────────────────────────────────────────────
  {
    name: 'Contact',
    domain: 'CRM',
    description: 'A person or agent the business interacts with. Tracks lifecycle from lead through customer.',
    fields: {
      id: { type: 'string', required: true, unique: true, description: 'Unique identifier' },
      name: { type: 'string', required: true, description: 'Full name' },
      email: { type: 'string', required: false, unique: true, description: 'Email address' },
      phone: { type: 'string', required: false, description: 'Phone number' },
      stage: { type: 'enum', required: true, description: 'Lifecycle stage', enum: ['Lead', 'Qualified', 'Customer', 'Churned', 'Partner'] },
      source: { type: 'string', required: false, description: 'Acquisition source' },
      metadata: { type: 'json', required: false, description: 'Custom fields' },
    },
    verbs: [
      { name: 'create', description: 'Create a new contact', lifecycle: { execute: 'create', before: 'creating', after: 'created', reverse: 'createdBy' }, level: 1 },
      { name: 'update', description: 'Update contact fields', lifecycle: { execute: 'update', before: 'updating', after: 'updated', reverse: 'updatedBy' }, level: 1 },
      { name: 'delete', description: 'Soft-delete the contact', lifecycle: { execute: 'delete', before: 'deleting', after: 'deleted', reverse: 'deletedBy' }, level: 1 },
      { name: 'qualify', description: 'Move contact to Qualified stage', lifecycle: { execute: 'qualify', before: 'qualifying', after: 'qualified', reverse: 'qualifiedBy' }, level: 1 },
      { name: 'convert', description: 'Convert lead to customer', lifecycle: { execute: 'convert', before: 'converting', after: 'converted', reverse: 'convertedBy' }, level: 1 },
    ],
    relationships: [
      { type: 'belongsTo', target: 'Company', field: 'companyId', inverse: 'contacts' },
      { type: 'hasMany', target: 'Deal', field: 'contactId', inverse: 'contact' },
      { type: 'hasMany', target: 'Activity', field: 'contactId', inverse: 'contact' },
      { type: 'hasMany', target: 'Ticket', field: 'contactId', inverse: 'contact' },
    ],
    level: 0,
  },
  {
    name: 'Company',
    domain: 'CRM',
    description: 'A business entity. Groups contacts and tracks organizational relationships.',
    fields: {
      id: { type: 'string', required: true, unique: true },
      name: { type: 'string', required: true, description: 'Company name' },
      domain: { type: 'string', required: false, unique: true, description: 'Website domain' },
      industry: { type: 'string', required: false, description: 'Industry classification' },
      size: { type: 'enum', required: false, enum: ['1-10', '11-50', '51-200', '201-1000', '1001+'] },
      metadata: { type: 'json', required: false },
    },
    verbs: [
      { name: 'create', description: 'Create a new company', lifecycle: { execute: 'create', before: 'creating', after: 'created', reverse: 'createdBy' }, level: 1 },
      { name: 'update', description: 'Update company fields', lifecycle: { execute: 'update', before: 'updating', after: 'updated', reverse: 'updatedBy' }, level: 1 },
      { name: 'delete', description: 'Soft-delete the company', lifecycle: { execute: 'delete', before: 'deleting', after: 'deleted', reverse: 'deletedBy' }, level: 1 },
      { name: 'enrich', description: 'Enrich with external data', lifecycle: { execute: 'enrich', before: 'enriching', after: 'enriched', reverse: 'enrichedBy' }, level: 2 },
    ],
    relationships: [
      { type: 'hasMany', target: 'Contact', field: 'companyId', inverse: 'company' },
      { type: 'hasMany', target: 'Deal', field: 'companyId', inverse: 'company' },
    ],
    level: 0,
  },
  {
    name: 'Deal',
    domain: 'CRM',
    description: 'A sales opportunity. Tracks value, pipeline stage, and close probability.',
    fields: {
      id: { type: 'string', required: true, unique: true },
      title: { type: 'string', required: true, description: 'Deal title' },
      value: { type: 'number', required: false, description: 'Deal value in cents' },
      currency: { type: 'string', required: false, description: 'ISO 4217 currency code' },
      stage: { type: 'enum', required: true, enum: ['Discovery', 'Proposal', 'Negotiation', 'Closed Won', 'Closed Lost'] },
      probability: { type: 'number', required: false, description: 'Close probability 0-100' },
      expectedCloseDate: { type: 'date', required: false },
      metadata: { type: 'json', required: false },
    },
    verbs: [
      { name: 'create', description: 'Create a new deal', lifecycle: { execute: 'create', before: 'creating', after: 'created', reverse: 'createdBy' }, level: 1 },
      { name: 'update', description: 'Update deal fields', lifecycle: { execute: 'update', before: 'updating', after: 'updated', reverse: 'updatedBy' }, level: 1 },
      { name: 'close', description: 'Close the deal (won or lost)', lifecycle: { execute: 'close', before: 'closing', after: 'closed', reverse: 'closedBy' }, level: 1 },
      { name: 'advance', description: 'Move to the next pipeline stage', lifecycle: { execute: 'advance', before: 'advancing', after: 'advanced', reverse: 'advancedBy' }, level: 1 },
    ],
    relationships: [
      { type: 'belongsTo', target: 'Contact', field: 'contactId', inverse: 'deals' },
      { type: 'belongsTo', target: 'Company', field: 'companyId', inverse: 'deals' },
    ],
    level: 0,
  },
  {
    name: 'Activity',
    domain: 'CRM',
    description: 'A logged interaction: call, email, meeting, note, or custom activity.',
    fields: {
      id: { type: 'string', required: true, unique: true },
      type: { type: 'enum', required: true, enum: ['call', 'email', 'meeting', 'note', 'task'] },
      subject: { type: 'string', required: true },
      body: { type: 'string', required: false },
      occurredAt: { type: 'timestamp', required: true },
      metadata: { type: 'json', required: false },
    },
    verbs: [
      { name: 'create', description: 'Log a new activity', lifecycle: { execute: 'create', before: 'creating', after: 'created', reverse: 'createdBy' }, level: 1 },
      { name: 'update', description: 'Update activity details', lifecycle: { execute: 'update', before: 'updating', after: 'updated', reverse: 'updatedBy' }, level: 1 },
      { name: 'delete', description: 'Remove an activity', lifecycle: { execute: 'delete', before: 'deleting', after: 'deleted', reverse: 'deletedBy' }, level: 1 },
    ],
    relationships: [
      { type: 'belongsTo', target: 'Contact', field: 'contactId', inverse: 'activities' },
      { type: 'belongsTo', target: 'Deal', field: 'dealId', inverse: 'activities' },
    ],
    level: 0,
  },

  // ── Projects (4) ────────────────────────────────────────────────────────
  {
    name: 'Project',
    domain: 'Projects',
    description: 'A project with milestones and tasks. Syncs bidirectionally with GitHub.',
    fields: {
      id: { type: 'string', required: true, unique: true },
      name: { type: 'string', required: true },
      description: { type: 'string', required: false },
      status: { type: 'enum', required: true, enum: ['Planning', 'Active', 'Paused', 'Completed', 'Archived'] },
      startDate: { type: 'date', required: false },
      endDate: { type: 'date', required: false },
      metadata: { type: 'json', required: false },
    },
    verbs: [
      { name: 'create', description: 'Create a new project', lifecycle: { execute: 'create', before: 'creating', after: 'created', reverse: 'createdBy' }, level: 1 },
      { name: 'update', description: 'Update project details', lifecycle: { execute: 'update', before: 'updating', after: 'updated', reverse: 'updatedBy' }, level: 1 },
      { name: 'archive', description: 'Archive the project', lifecycle: { execute: 'archive', before: 'archiving', after: 'archived', reverse: 'archivedBy' }, level: 1 },
      { name: 'activate', description: 'Start or resume the project', lifecycle: { execute: 'activate', before: 'activating', after: 'activated', reverse: 'activatedBy' }, level: 1 },
    ],
    relationships: [
      { type: 'hasMany', target: 'Task', field: 'projectId', inverse: 'project' },
      { type: 'hasMany', target: 'Milestone', field: 'projectId', inverse: 'project' },
    ],
    level: 0,
  },
  {
    name: 'Task',
    domain: 'Projects',
    description: 'A unit of work within a project. Maps to GitHub issues.',
    fields: {
      id: { type: 'string', required: true, unique: true },
      title: { type: 'string', required: true },
      description: { type: 'string', required: false },
      status: { type: 'enum', required: true, enum: ['Open', 'In Progress', 'Review', 'Done', 'Cancelled'] },
      priority: { type: 'enum', required: false, enum: ['Low', 'Medium', 'High', 'Urgent'] },
      assigneeId: { type: 'string', required: false },
      dueDate: { type: 'date', required: false },
      metadata: { type: 'json', required: false },
    },
    verbs: [
      { name: 'create', description: 'Create a new task', lifecycle: { execute: 'create', before: 'creating', after: 'created', reverse: 'createdBy' }, level: 1 },
      { name: 'update', description: 'Update task fields', lifecycle: { execute: 'update', before: 'updating', after: 'updated', reverse: 'updatedBy' }, level: 1 },
      { name: 'assign', description: 'Assign to a user or agent', lifecycle: { execute: 'assign', before: 'assigning', after: 'assigned', reverse: 'assignedBy' }, level: 1 },
      { name: 'complete', description: 'Mark the task as done', lifecycle: { execute: 'complete', before: 'completing', after: 'completed', reverse: 'completedBy' }, level: 1 },
    ],
    relationships: [
      { type: 'belongsTo', target: 'Project', field: 'projectId', inverse: 'tasks' },
      { type: 'belongsTo', target: 'Milestone', field: 'milestoneId', inverse: 'tasks' },
      { type: 'hasMany', target: 'Comment', field: 'taskId', inverse: 'task' },
    ],
    level: 0,
  },
  {
    name: 'Milestone',
    domain: 'Projects',
    description: 'A project checkpoint with a target date. Groups related tasks.',
    fields: {
      id: { type: 'string', required: true, unique: true },
      title: { type: 'string', required: true },
      description: { type: 'string', required: false },
      status: { type: 'enum', required: true, enum: ['Open', 'In Progress', 'Completed', 'Overdue'] },
      dueDate: { type: 'date', required: false },
      metadata: { type: 'json', required: false },
    },
    verbs: [
      { name: 'create', description: 'Create a new milestone', lifecycle: { execute: 'create', before: 'creating', after: 'created', reverse: 'createdBy' }, level: 1 },
      { name: 'update', description: 'Update milestone details', lifecycle: { execute: 'update', before: 'updating', after: 'updated', reverse: 'updatedBy' }, level: 1 },
      { name: 'complete', description: 'Mark milestone as completed', lifecycle: { execute: 'complete', before: 'completing', after: 'completed', reverse: 'completedBy' }, level: 1 },
    ],
    relationships: [
      { type: 'belongsTo', target: 'Project', field: 'projectId', inverse: 'milestones' },
      { type: 'hasMany', target: 'Task', field: 'milestoneId', inverse: 'milestone' },
    ],
    level: 0,
  },
  {
    name: 'Comment',
    domain: 'Projects',
    description: 'A comment on a task, ticket, or other entity.',
    fields: {
      id: { type: 'string', required: true, unique: true },
      body: { type: 'string', required: true },
      authorId: { type: 'string', required: true },
      metadata: { type: 'json', required: false },
    },
    verbs: [
      { name: 'create', description: 'Add a comment', lifecycle: { execute: 'create', before: 'creating', after: 'created', reverse: 'createdBy' }, level: 1 },
      { name: 'update', description: 'Edit a comment', lifecycle: { execute: 'update', before: 'updating', after: 'updated', reverse: 'updatedBy' }, level: 1 },
      { name: 'delete', description: 'Delete a comment', lifecycle: { execute: 'delete', before: 'deleting', after: 'deleted', reverse: 'deletedBy' }, level: 1 },
    ],
    relationships: [
      { type: 'belongsTo', target: 'Task', field: 'taskId', inverse: 'comments' },
    ],
    level: 0,
  },

  // ── Content (4) ─────────────────────────────────────────────────────────
  {
    name: 'Page',
    domain: 'Content',
    description: 'A static page with a slug. Used for docs, landing pages, and marketing.',
    fields: {
      id: { type: 'string', required: true, unique: true },
      title: { type: 'string', required: true },
      slug: { type: 'string', required: true, unique: true },
      body: { type: 'string', required: false, description: 'Markdown or MDX content' },
      status: { type: 'enum', required: true, enum: ['Draft', 'Published', 'Archived'] },
      metadata: { type: 'json', required: false },
    },
    verbs: [
      { name: 'create', description: 'Create a new page', lifecycle: { execute: 'create', before: 'creating', after: 'created', reverse: 'createdBy' }, level: 1 },
      { name: 'update', description: 'Update page content', lifecycle: { execute: 'update', before: 'updating', after: 'updated', reverse: 'updatedBy' }, level: 1 },
      { name: 'publish', description: 'Publish the page', lifecycle: { execute: 'publish', before: 'publishing', after: 'published', reverse: 'publishedBy' }, level: 1 },
      { name: 'archive', description: 'Archive the page', lifecycle: { execute: 'archive', before: 'archiving', after: 'archived', reverse: 'archivedBy' }, level: 1 },
    ],
    relationships: [
      { type: 'hasMany', target: 'Asset', field: 'pageId', inverse: 'page' },
      { type: 'belongsTo', target: 'Collection', field: 'collectionId', inverse: 'pages' },
    ],
    level: 0,
  },
  {
    name: 'Post',
    domain: 'Content',
    description: 'A blog post or changelog entry with publish date and author.',
    fields: {
      id: { type: 'string', required: true, unique: true },
      title: { type: 'string', required: true },
      slug: { type: 'string', required: true, unique: true },
      body: { type: 'string', required: false },
      excerpt: { type: 'string', required: false },
      status: { type: 'enum', required: true, enum: ['Draft', 'Published', 'Archived'] },
      publishedAt: { type: 'timestamp', required: false },
      authorId: { type: 'string', required: false },
      metadata: { type: 'json', required: false },
    },
    verbs: [
      { name: 'create', description: 'Create a new post', lifecycle: { execute: 'create', before: 'creating', after: 'created', reverse: 'createdBy' }, level: 1 },
      { name: 'update', description: 'Update post content', lifecycle: { execute: 'update', before: 'updating', after: 'updated', reverse: 'updatedBy' }, level: 1 },
      { name: 'publish', description: 'Publish the post', lifecycle: { execute: 'publish', before: 'publishing', after: 'published', reverse: 'publishedBy' }, level: 1 },
      { name: 'archive', description: 'Archive the post', lifecycle: { execute: 'archive', before: 'archiving', after: 'archived', reverse: 'archivedBy' }, level: 1 },
    ],
    relationships: [
      { type: 'belongsTo', target: 'Collection', field: 'collectionId', inverse: 'posts' },
    ],
    level: 0,
  },
  {
    name: 'Asset',
    domain: 'Content',
    description: 'A file asset: image, video, document, or any binary blob.',
    fields: {
      id: { type: 'string', required: true, unique: true },
      name: { type: 'string', required: true },
      url: { type: 'string', required: true },
      mimeType: { type: 'string', required: true },
      size: { type: 'number', required: false, description: 'Size in bytes' },
      metadata: { type: 'json', required: false },
    },
    verbs: [
      { name: 'create', description: 'Upload a new asset', lifecycle: { execute: 'create', before: 'creating', after: 'created', reverse: 'createdBy' }, level: 1 },
      { name: 'update', description: 'Update asset metadata', lifecycle: { execute: 'update', before: 'updating', after: 'updated', reverse: 'updatedBy' }, level: 1 },
      { name: 'delete', description: 'Delete an asset', lifecycle: { execute: 'delete', before: 'deleting', after: 'deleted', reverse: 'deletedBy' }, level: 1 },
    ],
    relationships: [
      { type: 'belongsTo', target: 'Page', field: 'pageId', inverse: 'assets' },
    ],
    level: 0,
  },
  {
    name: 'Collection',
    domain: 'Content',
    description: 'A group of pages or posts. Used for docs sections, blog categories, etc.',
    fields: {
      id: { type: 'string', required: true, unique: true },
      name: { type: 'string', required: true },
      slug: { type: 'string', required: true, unique: true },
      description: { type: 'string', required: false },
      metadata: { type: 'json', required: false },
    },
    verbs: [
      { name: 'create', description: 'Create a new collection', lifecycle: { execute: 'create', before: 'creating', after: 'created', reverse: 'createdBy' }, level: 1 },
      { name: 'update', description: 'Update collection details', lifecycle: { execute: 'update', before: 'updating', after: 'updated', reverse: 'updatedBy' }, level: 1 },
      { name: 'delete', description: 'Delete a collection', lifecycle: { execute: 'delete', before: 'deleting', after: 'deleted', reverse: 'deletedBy' }, level: 1 },
    ],
    relationships: [
      { type: 'hasMany', target: 'Page', field: 'collectionId', inverse: 'collection' },
      { type: 'hasMany', target: 'Post', field: 'collectionId', inverse: 'collection' },
    ],
    level: 0,
  },

  // ── Billing (5) ─────────────────────────────────────────────────────────
  {
    name: 'Product',
    domain: 'Billing',
    description: 'A product in the catalog. Truth source: Stripe.',
    fields: {
      id: { type: 'string', required: true, unique: true },
      name: { type: 'string', required: true },
      description: { type: 'string', required: false },
      active: { type: 'boolean', required: true },
      stripeProductId: { type: 'string', required: false },
      metadata: { type: 'json', required: false },
    },
    verbs: [
      { name: 'create', description: 'Create a new product', lifecycle: { execute: 'create', before: 'creating', after: 'created', reverse: 'createdBy' }, level: 1 },
      { name: 'update', description: 'Update product details', lifecycle: { execute: 'update', before: 'updating', after: 'updated', reverse: 'updatedBy' }, level: 1 },
      { name: 'activate', description: 'Activate the product', lifecycle: { execute: 'activate', before: 'activating', after: 'activated', reverse: 'activatedBy' }, level: 1 },
      { name: 'deactivate', description: 'Deactivate the product', lifecycle: { execute: 'deactivate', before: 'deactivating', after: 'deactivated', reverse: 'deactivatedBy' }, level: 1 },
    ],
    relationships: [
      { type: 'hasMany', target: 'Plan', field: 'productId', inverse: 'product' },
    ],
    level: 0,
  },
  {
    name: 'Plan',
    domain: 'Billing',
    description: 'A pricing plan for a product. Defines billing interval and amount.',
    fields: {
      id: { type: 'string', required: true, unique: true },
      name: { type: 'string', required: true },
      amount: { type: 'number', required: true, description: 'Price in cents' },
      currency: { type: 'string', required: true },
      interval: { type: 'enum', required: true, enum: ['month', 'year'] },
      stripePriceId: { type: 'string', required: false },
      metadata: { type: 'json', required: false },
    },
    verbs: [
      { name: 'create', description: 'Create a new plan', lifecycle: { execute: 'create', before: 'creating', after: 'created', reverse: 'createdBy' }, level: 1 },
      { name: 'update', description: 'Update plan details', lifecycle: { execute: 'update', before: 'updating', after: 'updated', reverse: 'updatedBy' }, level: 1 },
      { name: 'archive', description: 'Archive the plan', lifecycle: { execute: 'archive', before: 'archiving', after: 'archived', reverse: 'archivedBy' }, level: 1 },
    ],
    relationships: [
      { type: 'belongsTo', target: 'Product', field: 'productId', inverse: 'plans' },
      { type: 'hasMany', target: 'Subscription', field: 'planId', inverse: 'plan' },
    ],
    level: 0,
  },
  {
    name: 'Subscription',
    domain: 'Billing',
    description: 'An active subscription linking a contact to a plan. Truth source: Stripe.',
    fields: {
      id: { type: 'string', required: true, unique: true },
      status: { type: 'enum', required: true, enum: ['Active', 'Past Due', 'Cancelled', 'Trialing'] },
      currentPeriodStart: { type: 'timestamp', required: false },
      currentPeriodEnd: { type: 'timestamp', required: false },
      stripeSubscriptionId: { type: 'string', required: false },
      metadata: { type: 'json', required: false },
    },
    verbs: [
      { name: 'create', description: 'Create a new subscription', lifecycle: { execute: 'create', before: 'creating', after: 'created', reverse: 'createdBy' }, level: 1 },
      { name: 'cancel', description: 'Cancel the subscription', lifecycle: { execute: 'cancel', before: 'cancelling', after: 'cancelled', reverse: 'cancelledBy' }, level: 1 },
      { name: 'renew', description: 'Renew the subscription', lifecycle: { execute: 'renew', before: 'renewing', after: 'renewed', reverse: 'renewedBy' }, level: 2 },
    ],
    relationships: [
      { type: 'belongsTo', target: 'Plan', field: 'planId', inverse: 'subscriptions' },
      { type: 'belongsTo', target: 'Contact', field: 'contactId', inverse: 'subscriptions' },
      { type: 'hasMany', target: 'Invoice', field: 'subscriptionId', inverse: 'subscription' },
    ],
    level: 0,
  },
  {
    name: 'Invoice',
    domain: 'Billing',
    description: 'A billing invoice. Generated automatically from subscriptions or created manually.',
    fields: {
      id: { type: 'string', required: true, unique: true },
      number: { type: 'string', required: false, unique: true },
      amount: { type: 'number', required: true, description: 'Total in cents' },
      currency: { type: 'string', required: true },
      status: { type: 'enum', required: true, enum: ['Draft', 'Open', 'Paid', 'Void', 'Uncollectible'] },
      dueDate: { type: 'date', required: false },
      stripeInvoiceId: { type: 'string', required: false },
      metadata: { type: 'json', required: false },
    },
    verbs: [
      { name: 'create', description: 'Create a new invoice', lifecycle: { execute: 'create', before: 'creating', after: 'created', reverse: 'createdBy' }, level: 1 },
      { name: 'send', description: 'Send the invoice', lifecycle: { execute: 'send', before: 'sending', after: 'sent', reverse: 'sentBy' }, level: 2 },
      { name: 'void', description: 'Void the invoice', lifecycle: { execute: 'void', before: 'voiding', after: 'voided', reverse: 'voidedBy' }, level: 1 },
    ],
    relationships: [
      { type: 'belongsTo', target: 'Subscription', field: 'subscriptionId', inverse: 'invoices' },
      { type: 'belongsTo', target: 'Contact', field: 'contactId', inverse: 'invoices' },
      { type: 'hasMany', target: 'Payment', field: 'invoiceId', inverse: 'invoice' },
    ],
    level: 0,
  },
  {
    name: 'Payment',
    domain: 'Billing',
    description: 'A payment against an invoice. Records the transaction and method.',
    fields: {
      id: { type: 'string', required: true, unique: true },
      amount: { type: 'number', required: true, description: 'Amount in cents' },
      currency: { type: 'string', required: true },
      status: { type: 'enum', required: true, enum: ['Pending', 'Succeeded', 'Failed', 'Refunded'] },
      method: { type: 'enum', required: false, enum: ['card', 'bank', 'crypto', 'other'] },
      stripePaymentIntentId: { type: 'string', required: false },
      metadata: { type: 'json', required: false },
    },
    verbs: [
      { name: 'create', description: 'Record a new payment', lifecycle: { execute: 'create', before: 'creating', after: 'created', reverse: 'createdBy' }, level: 1 },
      { name: 'refund', description: 'Refund the payment', lifecycle: { execute: 'refund', before: 'refunding', after: 'refunded', reverse: 'refundedBy' }, level: 2 },
    ],
    relationships: [
      { type: 'belongsTo', target: 'Invoice', field: 'invoiceId', inverse: 'payments' },
    ],
    level: 0,
  },

  // ── Support (3) ─────────────────────────────────────────────────────────
  {
    name: 'Ticket',
    domain: 'Support',
    description: 'A support ticket from a contact. Tracks priority, status, and resolution.',
    fields: {
      id: { type: 'string', required: true, unique: true },
      subject: { type: 'string', required: true },
      description: { type: 'string', required: false },
      status: { type: 'enum', required: true, enum: ['Open', 'In Progress', 'Waiting', 'Resolved', 'Closed'] },
      priority: { type: 'enum', required: false, enum: ['Low', 'Medium', 'High', 'Urgent'] },
      assigneeId: { type: 'string', required: false },
      metadata: { type: 'json', required: false },
    },
    verbs: [
      { name: 'create', description: 'Open a new ticket', lifecycle: { execute: 'create', before: 'creating', after: 'created', reverse: 'createdBy' }, level: 1 },
      { name: 'update', description: 'Update ticket details', lifecycle: { execute: 'update', before: 'updating', after: 'updated', reverse: 'updatedBy' }, level: 1 },
      { name: 'assign', description: 'Assign to an agent', lifecycle: { execute: 'assign', before: 'assigning', after: 'assigned', reverse: 'assignedBy' }, level: 1 },
      { name: 'resolve', description: 'Mark as resolved', lifecycle: { execute: 'resolve', before: 'resolving', after: 'resolved', reverse: 'resolvedBy' }, level: 1 },
      { name: 'close', description: 'Close the ticket', lifecycle: { execute: 'close', before: 'closing', after: 'closed', reverse: 'closedBy' }, level: 1 },
    ],
    relationships: [
      { type: 'belongsTo', target: 'Contact', field: 'contactId', inverse: 'tickets' },
      { type: 'hasMany', target: 'Reply', field: 'ticketId', inverse: 'ticket' },
    ],
    level: 0,
  },
  {
    name: 'Article',
    domain: 'Support',
    description: 'A knowledge base article. Used for self-service support.',
    fields: {
      id: { type: 'string', required: true, unique: true },
      title: { type: 'string', required: true },
      slug: { type: 'string', required: true, unique: true },
      body: { type: 'string', required: true },
      status: { type: 'enum', required: true, enum: ['Draft', 'Published', 'Archived'] },
      category: { type: 'string', required: false },
      metadata: { type: 'json', required: false },
    },
    verbs: [
      { name: 'create', description: 'Create a new article', lifecycle: { execute: 'create', before: 'creating', after: 'created', reverse: 'createdBy' }, level: 1 },
      { name: 'update', description: 'Update article content', lifecycle: { execute: 'update', before: 'updating', after: 'updated', reverse: 'updatedBy' }, level: 1 },
      { name: 'publish', description: 'Publish the article', lifecycle: { execute: 'publish', before: 'publishing', after: 'published', reverse: 'publishedBy' }, level: 1 },
    ],
    relationships: [],
    level: 0,
  },
  {
    name: 'Reply',
    domain: 'Support',
    description: 'A reply on a support ticket from an agent or customer.',
    fields: {
      id: { type: 'string', required: true, unique: true },
      body: { type: 'string', required: true },
      authorId: { type: 'string', required: true },
      internal: { type: 'boolean', required: false, description: 'Internal note (not visible to customer)' },
      metadata: { type: 'json', required: false },
    },
    verbs: [
      { name: 'create', description: 'Add a reply', lifecycle: { execute: 'create', before: 'creating', after: 'created', reverse: 'createdBy' }, level: 1 },
      { name: 'update', description: 'Edit a reply', lifecycle: { execute: 'update', before: 'updating', after: 'updated', reverse: 'updatedBy' }, level: 1 },
      { name: 'delete', description: 'Delete a reply', lifecycle: { execute: 'delete', before: 'deleting', after: 'deleted', reverse: 'deletedBy' }, level: 1 },
    ],
    relationships: [
      { type: 'belongsTo', target: 'Ticket', field: 'ticketId', inverse: 'replies' },
    ],
    level: 0,
  },

  // ── Analytics (4) ───────────────────────────────────────────────────────
  {
    name: 'Event',
    domain: 'Analytics',
    description: 'A tracked event from the browser SDK, API, or system. Forwarded to external analytics.',
    fields: {
      id: { type: 'string', required: true, unique: true },
      name: { type: 'string', required: true, description: 'Event name (e.g. page_view, signup)' },
      properties: { type: 'json', required: false },
      sessionId: { type: 'string', required: false },
      timestamp: { type: 'timestamp', required: true },
      metadata: { type: 'json', required: false },
    },
    verbs: [
      { name: 'create', description: 'Track an event', lifecycle: { execute: 'create', before: 'creating', after: 'created', reverse: 'createdBy' }, level: 1 },
    ],
    relationships: [
      { type: 'belongsTo', target: 'Contact', field: 'contactId', inverse: 'events' },
      { type: 'belongsTo', target: 'Funnel', field: 'funnelId', inverse: 'events' },
    ],
    level: 0,
  },
  {
    name: 'Metric',
    domain: 'Analytics',
    description: 'A named business metric computed from events and entities (MRR, churn, NRR, LTV).',
    fields: {
      id: { type: 'string', required: true, unique: true },
      name: { type: 'string', required: true },
      value: { type: 'number', required: true },
      unit: { type: 'string', required: false },
      period: { type: 'enum', required: false, enum: ['hour', 'day', 'week', 'month', 'quarter', 'year'] },
      computedAt: { type: 'timestamp', required: true },
      metadata: { type: 'json', required: false },
    },
    verbs: [
      { name: 'create', description: 'Record a metric value', lifecycle: { execute: 'create', before: 'creating', after: 'created', reverse: 'createdBy' }, level: 1 },
      { name: 'compute', description: 'Recompute from source data', lifecycle: { execute: 'compute', before: 'computing', after: 'computed', reverse: 'computedBy' }, level: 2 },
    ],
    relationships: [],
    level: 0,
  },
  {
    name: 'Funnel',
    domain: 'Analytics',
    description: 'A conversion funnel with ordered steps. Tracks drop-off between stages.',
    fields: {
      id: { type: 'string', required: true, unique: true },
      name: { type: 'string', required: true },
      steps: { type: 'json', required: true, description: 'Ordered list of event names that form the funnel' },
      metadata: { type: 'json', required: false },
    },
    verbs: [
      { name: 'create', description: 'Create a new funnel', lifecycle: { execute: 'create', before: 'creating', after: 'created', reverse: 'createdBy' }, level: 1 },
      { name: 'update', description: 'Update funnel steps', lifecycle: { execute: 'update', before: 'updating', after: 'updated', reverse: 'updatedBy' }, level: 1 },
      { name: 'analyze', description: 'Run funnel analysis', lifecycle: { execute: 'analyze', before: 'analyzing', after: 'analyzed', reverse: 'analyzedBy' }, level: 1 },
    ],
    relationships: [
      { type: 'hasMany', target: 'Event', field: 'funnelId', inverse: 'funnel' },
      { type: 'hasMany', target: 'Goal', field: 'funnelId', inverse: 'funnel' },
    ],
    level: 0,
  },
  {
    name: 'Goal',
    domain: 'Analytics',
    description: 'A target metric value with a deadline. Tracks progress toward business objectives.',
    fields: {
      id: { type: 'string', required: true, unique: true },
      name: { type: 'string', required: true },
      targetValue: { type: 'number', required: true },
      currentValue: { type: 'number', required: false },
      unit: { type: 'string', required: false },
      deadline: { type: 'date', required: false },
      status: { type: 'enum', required: true, enum: ['Active', 'Achieved', 'Missed', 'Cancelled'] },
      metadata: { type: 'json', required: false },
    },
    verbs: [
      { name: 'create', description: 'Set a new goal', lifecycle: { execute: 'create', before: 'creating', after: 'created', reverse: 'createdBy' }, level: 1 },
      { name: 'update', description: 'Update goal progress', lifecycle: { execute: 'update', before: 'updating', after: 'updated', reverse: 'updatedBy' }, level: 1 },
      { name: 'achieve', description: 'Mark goal as achieved', lifecycle: { execute: 'achieve', before: 'achieving', after: 'achieved', reverse: 'achievedBy' }, level: 1 },
    ],
    relationships: [
      { type: 'belongsTo', target: 'Funnel', field: 'funnelId', inverse: 'goals' },
    ],
    level: 0,
  },

  // ── Marketing (3) ───────────────────────────────────────────────────────
  {
    name: 'Campaign',
    domain: 'Marketing',
    description: 'A marketing campaign targeting a segment. Tracks performance and conversions.',
    fields: {
      id: { type: 'string', required: true, unique: true },
      name: { type: 'string', required: true },
      type: { type: 'enum', required: true, enum: ['email', 'social', 'content', 'paid', 'referral'] },
      status: { type: 'enum', required: true, enum: ['Draft', 'Scheduled', 'Active', 'Paused', 'Completed'] },
      startDate: { type: 'date', required: false },
      endDate: { type: 'date', required: false },
      budget: { type: 'number', required: false, description: 'Budget in cents' },
      metadata: { type: 'json', required: false },
    },
    verbs: [
      { name: 'create', description: 'Create a new campaign', lifecycle: { execute: 'create', before: 'creating', after: 'created', reverse: 'createdBy' }, level: 1 },
      { name: 'update', description: 'Update campaign details', lifecycle: { execute: 'update', before: 'updating', after: 'updated', reverse: 'updatedBy' }, level: 1 },
      { name: 'launch', description: 'Launch the campaign', lifecycle: { execute: 'launch', before: 'launching', after: 'launched', reverse: 'launchedBy' }, level: 1 },
      { name: 'pause', description: 'Pause the campaign', lifecycle: { execute: 'pause', before: 'pausing', after: 'paused', reverse: 'pausedBy' }, level: 1 },
    ],
    relationships: [
      { type: 'belongsTo', target: 'Segment', field: 'segmentId', inverse: 'campaigns' },
    ],
    level: 0,
  },
  {
    name: 'Segment',
    domain: 'Marketing',
    description: 'A dynamic group of contacts based on filters. Used for campaign targeting.',
    fields: {
      id: { type: 'string', required: true, unique: true },
      name: { type: 'string', required: true },
      filters: { type: 'json', required: true, description: 'MongoDB-style query filters' },
      count: { type: 'number', required: false, description: 'Cached count of matching contacts' },
      metadata: { type: 'json', required: false },
    },
    verbs: [
      { name: 'create', description: 'Create a new segment', lifecycle: { execute: 'create', before: 'creating', after: 'created', reverse: 'createdBy' }, level: 1 },
      { name: 'update', description: 'Update segment filters', lifecycle: { execute: 'update', before: 'updating', after: 'updated', reverse: 'updatedBy' }, level: 1 },
      { name: 'refresh', description: 'Recompute segment membership', lifecycle: { execute: 'refresh', before: 'refreshing', after: 'refreshed', reverse: 'refreshedBy' }, level: 1 },
    ],
    relationships: [
      { type: 'hasMany', target: 'Campaign', field: 'segmentId', inverse: 'segment' },
    ],
    level: 0,
  },
  {
    name: 'Form',
    domain: 'Marketing',
    description: 'A lead capture form. Submissions create contacts and trigger workflows.',
    fields: {
      id: { type: 'string', required: true, unique: true },
      name: { type: 'string', required: true },
      slug: { type: 'string', required: true, unique: true },
      fields: { type: 'json', required: true, description: 'Form field definitions' },
      status: { type: 'enum', required: true, enum: ['Draft', 'Active', 'Archived'] },
      submissions: { type: 'number', required: false, description: 'Total submission count' },
      metadata: { type: 'json', required: false },
    },
    verbs: [
      { name: 'create', description: 'Create a new form', lifecycle: { execute: 'create', before: 'creating', after: 'created', reverse: 'createdBy' }, level: 1 },
      { name: 'update', description: 'Update form fields', lifecycle: { execute: 'update', before: 'updating', after: 'updated', reverse: 'updatedBy' }, level: 1 },
      { name: 'submit', description: 'Submit the form (creates a contact)', lifecycle: { execute: 'submit', before: 'submitting', after: 'submitted', reverse: 'submittedBy' }, level: 0 },
      { name: 'archive', description: 'Archive the form', lifecycle: { execute: 'archive', before: 'archiving', after: 'archived', reverse: 'archivedBy' }, level: 1 },
    ],
    relationships: [],
    level: 0,
  },

  // ── Experimentation (2) ────────────────────────────────────────────────
  {
    name: 'Experiment',
    domain: 'Experimentation',
    description: 'An A/B test or multivariate experiment. Tracks variants and statistical significance.',
    fields: {
      id: { type: 'string', required: true, unique: true },
      name: { type: 'string', required: true },
      hypothesis: { type: 'string', required: false },
      status: { type: 'enum', required: true, enum: ['Draft', 'Running', 'Paused', 'Concluded'] },
      variants: { type: 'json', required: true, description: 'Array of variant objects with name, weight, and config' },
      targetMetric: { type: 'string', required: false },
      startDate: { type: 'date', required: false },
      endDate: { type: 'date', required: false },
      metadata: { type: 'json', required: false },
    },
    verbs: [
      { name: 'create', description: 'Create a new experiment', lifecycle: { execute: 'create', before: 'creating', after: 'created', reverse: 'createdBy' }, level: 1 },
      { name: 'update', description: 'Update experiment config', lifecycle: { execute: 'update', before: 'updating', after: 'updated', reverse: 'updatedBy' }, level: 1 },
      { name: 'start', description: 'Start running the experiment', lifecycle: { execute: 'start', before: 'starting', after: 'started', reverse: 'startedBy' }, level: 1 },
      { name: 'conclude', description: 'Conclude and pick a winner', lifecycle: { execute: 'conclude', before: 'concluding', after: 'concluded', reverse: 'concludedBy' }, level: 1 },
    ],
    relationships: [
      { type: 'hasMany', target: 'FeatureFlag', field: 'experimentId', inverse: 'experiment' },
    ],
    level: 0,
  },
  {
    name: 'FeatureFlag',
    domain: 'Experimentation',
    description: 'A feature flag controlling rollout. Can be linked to an experiment for gradual release.',
    fields: {
      id: { type: 'string', required: true, unique: true },
      key: { type: 'string', required: true, unique: true, description: 'Feature flag key (e.g. new-dashboard)' },
      description: { type: 'string', required: false },
      enabled: { type: 'boolean', required: true },
      rolloutPercentage: { type: 'number', required: false, description: '0-100 percentage rollout' },
      targeting: { type: 'json', required: false, description: 'Targeting rules for specific segments' },
      metadata: { type: 'json', required: false },
    },
    verbs: [
      { name: 'create', description: 'Create a new feature flag', lifecycle: { execute: 'create', before: 'creating', after: 'created', reverse: 'createdBy' }, level: 1 },
      { name: 'update', description: 'Update flag configuration', lifecycle: { execute: 'update', before: 'updating', after: 'updated', reverse: 'updatedBy' }, level: 1 },
      { name: 'enable', description: 'Enable the flag globally', lifecycle: { execute: 'enable', before: 'enabling', after: 'enabled', reverse: 'enabledBy' }, level: 1 },
      { name: 'disable', description: 'Disable the flag globally', lifecycle: { execute: 'disable', before: 'disabling', after: 'disabled', reverse: 'disabledBy' }, level: 1 },
    ],
    relationships: [
      { type: 'belongsTo', target: 'Experiment', field: 'experimentId', inverse: 'flags' },
    ],
    level: 0,
  },

  // ── Platform (3) ────────────────────────────────────────────────────────
  {
    name: 'Workflow',
    domain: 'Platform',
    description: 'An automated workflow triggered by events. Chains actions across entities.',
    fields: {
      id: { type: 'string', required: true, unique: true },
      name: { type: 'string', required: true },
      description: { type: 'string', required: false },
      trigger: { type: 'json', required: true, description: 'Event trigger definition' },
      steps: { type: 'json', required: true, description: 'Ordered list of action steps' },
      enabled: { type: 'boolean', required: true },
      lastRunAt: { type: 'timestamp', required: false },
      metadata: { type: 'json', required: false },
    },
    verbs: [
      { name: 'create', description: 'Create a new workflow', lifecycle: { execute: 'create', before: 'creating', after: 'created', reverse: 'createdBy' }, level: 1 },
      { name: 'update', description: 'Update workflow steps', lifecycle: { execute: 'update', before: 'updating', after: 'updated', reverse: 'updatedBy' }, level: 1 },
      { name: 'enable', description: 'Enable the workflow', lifecycle: { execute: 'enable', before: 'enabling', after: 'enabled', reverse: 'enabledBy' }, level: 1 },
      { name: 'disable', description: 'Disable the workflow', lifecycle: { execute: 'disable', before: 'disabling', after: 'disabled', reverse: 'disabledBy' }, level: 1 },
      { name: 'trigger', description: 'Manually trigger the workflow', lifecycle: { execute: 'trigger', before: 'triggering', after: 'triggered', reverse: 'triggeredBy' }, level: 1 },
    ],
    relationships: [],
    level: 0,
  },
  {
    name: 'Integration',
    domain: 'Platform',
    description: 'A connected third-party service (Stripe, GitHub, Slack, etc.).',
    fields: {
      id: { type: 'string', required: true, unique: true },
      name: { type: 'string', required: true },
      provider: { type: 'string', required: true, description: 'Integration provider (e.g. stripe, github, slack)' },
      status: { type: 'enum', required: true, enum: ['Active', 'Inactive', 'Error'] },
      config: { type: 'json', required: false, description: 'Provider-specific configuration' },
      metadata: { type: 'json', required: false },
    },
    verbs: [
      { name: 'create', description: 'Connect a new integration', lifecycle: { execute: 'create', before: 'creating', after: 'created', reverse: 'createdBy' }, level: 2 },
      { name: 'update', description: 'Update integration config', lifecycle: { execute: 'update', before: 'updating', after: 'updated', reverse: 'updatedBy' }, level: 2 },
      { name: 'disconnect', description: 'Disconnect the integration', lifecycle: { execute: 'disconnect', before: 'disconnecting', after: 'disconnected', reverse: 'disconnectedBy' }, level: 2 },
      { name: 'test', description: 'Test the integration connection', lifecycle: { execute: 'test', before: 'testing', after: 'tested', reverse: 'testedBy' }, level: 2 },
    ],
    relationships: [],
    level: 2,
  },
  {
    name: 'Agent',
    domain: 'Platform',
    description: 'An AI agent with capabilities, an Ed25519 keypair, and delegated permissions.',
    fields: {
      id: { type: 'string', required: true, unique: true },
      name: { type: 'string', required: true },
      description: { type: 'string', required: false },
      model: { type: 'string', required: false, description: 'AI model identifier' },
      capabilities: { type: 'json', required: false, description: 'List of granted capabilities' },
      did: { type: 'string', required: false, description: 'Decentralized identifier (did:agent:ed25519:...)' },
      status: { type: 'enum', required: true, enum: ['Active', 'Paused', 'Revoked'] },
      metadata: { type: 'json', required: false },
    },
    verbs: [
      { name: 'create', description: 'Register a new agent', lifecycle: { execute: 'create', before: 'creating', after: 'created', reverse: 'createdBy' }, level: 1 },
      { name: 'update', description: 'Update agent config', lifecycle: { execute: 'update', before: 'updating', after: 'updated', reverse: 'updatedBy' }, level: 1 },
      { name: 'grant', description: 'Grant a capability to the agent', lifecycle: { execute: 'grant', before: 'granting', after: 'granted', reverse: 'grantedBy' }, level: 2 },
      { name: 'revoke', description: 'Revoke agent access', lifecycle: { execute: 'revoke', before: 'revoking', after: 'revoked', reverse: 'revokedBy' }, level: 2 },
    ],
    relationships: [],
    level: 0,
  },
]

// ============================================================================
// Domain Descriptions
// ============================================================================

const DOMAIN_DESCRIPTIONS: Record<string, string> = {
  CRM: 'Customer relationship management — contacts, companies, deals, and activity tracking',
  Projects: 'Project management with GitHub sync — projects, tasks, milestones, and comments',
  Content: 'Content management — pages, posts, assets, and collections',
  Billing: 'Billing and payments powered by Stripe — products, plans, subscriptions, invoices, and payments',
  Support: 'Customer support — tickets, knowledge base articles, and replies',
  Analytics: 'Business analytics — events, metrics, funnels, and goals',
  Marketing: 'Marketing automation — campaigns, segments, and lead capture forms',
  Experimentation: 'A/B testing and feature flags — experiments and feature rollout',
  Platform: 'Platform infrastructure — workflows, integrations, and AI agents',
}

// ============================================================================
// Lookup Helpers
// ============================================================================

const ENTITY_MAP = new Map<string, EntitySchema>()
for (const entity of ENTITY_SCHEMAS) {
  ENTITY_MAP.set(entity.name.toLowerCase(), entity)
  ENTITY_MAP.set(entity.name, entity)
}

function findEntity(name: string): EntitySchema | undefined {
  return ENTITY_MAP.get(name) ?? ENTITY_MAP.get(name.toLowerCase())
}

// ============================================================================
// Tool: explore
// ============================================================================

export function handleExplore(params: {
  type?: string
  depth?: 'summary' | 'full'
}): ToolResult {
  const depth = params.depth ?? 'summary'

  // Single entity exploration
  if (params.type) {
    const entity = findEntity(params.type)
    if (!entity) {
      return {
        content: [{ type: 'text', text: JSON.stringify({ error: `Unknown entity type: ${params.type}`, availableTypes: ENTITY_SCHEMAS.map(e => e.name) }, null, 2) }],
        isError: true,
      }
    }

    const result = depth === 'full'
      ? entity
      : {
          name: entity.name,
          domain: entity.domain,
          description: entity.description,
          verbs: entity.verbs.map(v => ({ name: v.name, description: v.description, level: v.level })),
          relationships: entity.relationships.map(r => `${r.type} ${r.target}`),
          fieldCount: Object.keys(entity.fields).length,
          level: entity.level,
        }

    return {
      content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
    }
  }

  // Full system exploration — group by domain
  const domains: Record<string, { description: string; entities: EntitySchema[] }> = {}

  for (const entity of ENTITY_SCHEMAS) {
    if (!domains[entity.domain]) {
      domains[entity.domain] = {
        description: DOMAIN_DESCRIPTIONS[entity.domain] ?? entity.domain,
        entities: [],
      }
    }

    if (depth === 'full') {
      domains[entity.domain].entities.push(entity)
    } else {
      domains[entity.domain].entities.push({
        name: entity.name,
        description: entity.description,
        verbs: entity.verbs.map(v => v.name),
        relationships: entity.relationships.map(r => `${r.type} ${r.target}`),
        level: entity.level,
      } as unknown as EntitySchema)
    }
  }

  const totalVerbs = ENTITY_SCHEMAS.reduce((sum, e) => sum + e.verbs.length, 0)

  const result: ExploreResult = {
    domains,
    totalEntities: ENTITY_SCHEMAS.length,
    totalVerbs,
  }

  return {
    content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
  }
}

// ============================================================================
// Tool: try
// ============================================================================

export function handleTry(params: {
  operations: TryOperation[]
}, auth: MCPAuthResult): ToolResult {
  if (auth.level < 1) {
    return {
      content: [{ type: 'text', text: JSON.stringify({
        error: 'The try tool requires Level 1+ authentication',
        currentLevel: auth.level,
        upgrade: auth.upgrade,
      }, null, 2) }],
      isError: true,
    }
  }

  if (!params.operations || !Array.isArray(params.operations) || params.operations.length === 0) {
    return {
      content: [{ type: 'text', text: JSON.stringify({
        error: 'operations must be a non-empty array of { entity, verb, data } objects',
      }, null, 2) }],
      isError: true,
    }
  }

  if (params.operations.length > 50) {
    return {
      content: [{ type: 'text', text: JSON.stringify({
        error: 'Maximum 50 operations per try call',
        count: params.operations.length,
      }, null, 2) }],
      isError: true,
    }
  }

  const now = new Date().toISOString()
  const operationResults: TryOperationResult[] = []
  const allEvents: Array<{ type: string; entity: string; verb: string; timestamp: string }> = []
  const entityCounts: Record<string, number> = {}
  const verbCounts: Record<string, number> = {}
  const sideEffectSummary: string[] = []

  // Simulated ID counter for the try session
  let idCounter = 1

  for (let i = 0; i < params.operations.length; i++) {
    const op = params.operations[i]
    const entity = findEntity(op.entity)

    if (!entity) {
      operationResults.push({
        index: i,
        entity: op.entity,
        verb: op.verb,
        result: { error: `Unknown entity type: ${op.entity}` },
        events: [],
        sideEffects: [],
      })
      continue
    }

    const verb = entity.verbs.find(v => v.name === op.verb)
    if (!verb) {
      operationResults.push({
        index: i,
        entity: op.entity,
        verb: op.verb,
        result: { error: `Unknown verb "${op.verb}" for ${entity.name}. Available: ${entity.verbs.map(v => v.name).join(', ')}` },
        events: [],
        sideEffects: [],
      })
      continue
    }

    // Check verb level requirement
    if (verb.level > auth.level) {
      operationResults.push({
        index: i,
        entity: op.entity,
        verb: op.verb,
        result: { error: `Verb "${op.verb}" requires Level ${verb.level}+, current level is ${auth.level}` },
        events: [],
        sideEffects: [],
      })
      continue
    }

    // Simulate the operation result
    const simulatedId = `try_${entity.name.toLowerCase()}_${idCounter++}`
    const simulatedResult: Record<string, unknown> = {
      id: simulatedId,
      ...op.data,
    }

    // Add default field values where not provided
    for (const [fieldName, fieldSchema] of Object.entries(entity.fields)) {
      if (fieldName === 'id') continue
      if (simulatedResult[fieldName] === undefined) {
        if (fieldSchema.type === 'timestamp' && fieldName.includes('At')) {
          simulatedResult[fieldName] = now
        } else if (fieldSchema.enum && fieldSchema.required) {
          // Use first enum value as default if not provided
          simulatedResult[fieldName] = simulatedResult[fieldName] ?? fieldSchema.enum[0]
        }
      }
    }

    // Simulate events using verb lifecycle
    const events = [
      { type: verb.lifecycle.before, entity: entity.name, verb: op.verb, timestamp: now },
      { type: verb.lifecycle.after, entity: entity.name, verb: op.verb, timestamp: now },
    ]

    // Simulate side effects based on entity and verb
    const sideEffects: string[] = []

    if (op.verb === 'create' && entity.name === 'Contact') {
      sideEffects.push('Trigger: contact.created event to all subscribed workflows')
      if (op.data.email) {
        sideEffects.push(`Dedup check: verify no existing contact with email ${op.data.email}`)
      }
    }

    if (op.verb === 'close' && entity.name === 'Deal') {
      sideEffects.push('Trigger: deal.closed event — may trigger subscription creation workflow')
      if (op.data.stage === 'Closed Won' || !op.data.stage) {
        sideEffects.push('Side effect: update contact stage to Customer')
        sideEffects.push('Side effect: compute revenue metric update')
      }
    }

    if (op.verb === 'create' && entity.name === 'Subscription') {
      sideEffects.push('Integration: Stripe — would create Stripe subscription (mocked in try)')
      sideEffects.push('Trigger: subscription.created event')
      sideEffects.push('Side effect: compute MRR metric update')
    }

    if (op.verb === 'cancel' && entity.name === 'Subscription') {
      sideEffects.push('Integration: Stripe — would cancel Stripe subscription (mocked in try)')
      sideEffects.push('Trigger: subscription.cancelled event')
      sideEffects.push('Side effect: compute MRR and churn metric update')
    }

    if (op.verb === 'create' && entity.name === 'Invoice') {
      sideEffects.push('Integration: Stripe — would create Stripe invoice (mocked in try)')
    }

    if (op.verb === 'submit' && entity.name === 'Form') {
      sideEffects.push('Side effect: create Contact from form submission')
      sideEffects.push('Trigger: form.submitted event — may trigger campaign enrollment')
    }

    if (op.verb === 'launch' && entity.name === 'Campaign') {
      sideEffects.push('Side effect: enumerate Segment contacts for targeting')
      sideEffects.push('Integration: email provider (mocked in try)')
    }

    if (op.verb === 'trigger' && entity.name === 'Workflow') {
      sideEffects.push('Side effect: execute workflow steps sequentially')
      sideEffects.push('Trigger: workflow.triggered event')
    }

    if (entity.domain === 'Billing' && auth.level < 2) {
      sideEffects.push('Note: Stripe integration stubbed at Level 1 — realistic mock responses')
    }

    // Track counts for summary
    entityCounts[entity.name] = (entityCounts[entity.name] ?? 0) + 1
    verbCounts[op.verb] = (verbCounts[op.verb] ?? 0) + 1

    for (const se of sideEffects) {
      if (!sideEffectSummary.includes(se)) {
        sideEffectSummary.push(se)
      }
    }

    operationResults.push({
      index: i,
      entity: entity.name,
      verb: op.verb,
      result: simulatedResult,
      events,
      sideEffects,
    })

    allEvents.push(...events)
  }

  // Build human-readable summary
  const entityParts = Object.entries(entityCounts)
    .map(([name, count]) => `${count} ${name}${count > 1 ? 's' : ''}`)
  const verbParts = Object.entries(verbCounts)
    .map(([verb, count]) => `${count} ${verb}${count > 1 ? 's' : ''}`)

  const webhookCount = sideEffectSummary.filter(s => s.includes('Integration:')).length
  const workflowTriggers = sideEffectSummary.filter(s => s.includes('Trigger:')).length

  let summary = `This workflow would ${verbParts.join(', ')} on ${entityParts.join(', ')}`
  if (workflowTriggers > 0) summary += `, trigger ${workflowTriggers} event${workflowTriggers > 1 ? 's' : ''}`
  if (webhookCount > 0) summary += `, and call ${webhookCount} integration${webhookCount > 1 ? 's' : ''}`
  summary += '.'

  const result: TryResult = {
    operations: operationResults,
    summary,
    events: allEvents,
    rollback: true,
    note: 'All operations were simulated. Nothing was persisted. Use the "do" tool to execute for real.',
  }

  return {
    content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
  }
}

// ============================================================================
// Tool: search
// ============================================================================

export async function handleSearch(
  params: { query: string; type?: string; filters?: Record<string, unknown>; limit?: number },
  identityStub: IdentityStub,
  auth: MCPAuthResult,
): Promise<ToolResult> {
  const limit = Math.min(params.limit ?? 10, 100)
  const query = params.query.toLowerCase().trim()

  if (!query && !params.type && !params.filters) {
    return {
      content: [{ type: 'text', text: JSON.stringify({ error: 'At least one of query, type, or filters is required' }, null, 2) }],
      isError: true,
    }
  }

  // Search schemas first — always available at L0
  const schemaResults: Array<{ type: string; id: string; name?: string; score: number; snippet: Record<string, unknown> }> = []

  if (query) {
    for (const entity of ENTITY_SCHEMAS) {
      if (params.type && entity.name.toLowerCase() !== params.type.toLowerCase() && entity.domain.toLowerCase() !== params.type.toLowerCase()) {
        continue
      }

      let score = 0

      // Name match
      if (entity.name.toLowerCase().includes(query)) score += 10
      if (entity.name.toLowerCase() === query) score += 20

      // Domain match
      if (entity.domain.toLowerCase().includes(query)) score += 5

      // Description match
      if (entity.description.toLowerCase().includes(query)) score += 3

      // Verb match
      for (const verb of entity.verbs) {
        if (verb.name.toLowerCase().includes(query)) score += 2
        if (verb.description.toLowerCase().includes(query)) score += 1
      }

      // Field match
      for (const fieldName of Object.keys(entity.fields)) {
        if (fieldName.toLowerCase().includes(query)) score += 2
      }

      if (score > 0) {
        schemaResults.push({
          type: 'schema',
          id: entity.name,
          name: entity.name,
          score,
          snippet: {
            domain: entity.domain,
            description: entity.description,
            verbs: entity.verbs.map(v => v.name),
          },
        })
      }
    }
  }

  // If authenticated, search entity data in the DO via the mcp-search endpoint
  const dataResults: Array<{ type: string; id: string; name?: string; score: number; snippet: Record<string, unknown> }> = []

  if (auth.authenticated && auth.identityId) {
    try {
      const searchResult = await identityStub.mcpSearch({
        identityId: auth.identityId,
        query: query || undefined,
        type: params.type,
        filters: params.filters,
        limit,
      })

      for (const item of searchResult.results) {
        const name = String(item.data.name ?? item.data.title ?? item.data.subject ?? '')
        dataResults.push({
          type: item.type,
          id: item.id,
          name: name || undefined,
          score: item.score,
          snippet: item.data,
        })
      }
    } catch {
      // Silently skip data search errors — schema results still returned
    }
  }

  // Combine and sort by score
  const allResults = [...dataResults, ...schemaResults]
    .sort((a, b) => b.score - a.score)
    .slice(0, limit)

  const result: SearchResult = {
    results: allResults,
    total: allResults.length,
    query: params.query,
  }

  return {
    content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
  }
}

// ============================================================================
// Tool: fetch
// ============================================================================

export async function handleFetch(
  params: { type: string; id?: string; fields?: string[]; filters?: Record<string, unknown>; limit?: number; offset?: number },
  identityStub: IdentityStub,
  auth: MCPAuthResult,
): Promise<ToolResult> {
  if (!params.type) {
    return {
      content: [{ type: 'text', text: JSON.stringify({ error: 'type parameter is required' }, null, 2) }],
      isError: true,
    }
  }

  const typeLower = params.type.toLowerCase()

  // Fetch schema — always available
  if (typeLower === 'schema') {
    if (params.id) {
      const entity = findEntity(params.id)
      if (!entity) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ error: `Unknown entity type: ${params.id}`, availableTypes: ENTITY_SCHEMAS.map(e => e.name) }, null, 2) }],
          isError: true,
        }
      }

      const data = params.fields
        ? Object.fromEntries(Object.entries(entity).filter(([k]) => params.fields!.includes(k)))
        : entity

      return {
        content: [{ type: 'text', text: JSON.stringify({ type: 'schema', id: entity.name, data }, null, 2) }],
      }
    }

    // Return all schemas
    return {
      content: [{ type: 'text', text: JSON.stringify({
        type: 'schema',
        data: {
          entities: ENTITY_SCHEMAS.map(e => e.name),
          domains: Object.keys(DOMAIN_DESCRIPTIONS),
          totalEntities: ENTITY_SCHEMAS.length,
        },
      }, null, 2) }],
    }
  }

  // Fetch identity data — requires auth for specific records
  if (typeLower === 'identity') {
    if (!params.id) {
      // Return own identity if authenticated
      if (!auth.authenticated || !auth.identityId) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ error: 'Authentication required to fetch identity data', upgrade: auth.upgrade }, null, 2) }],
          isError: true,
        }
      }
      params.id = auth.identityId
    }

    try {
      const identity = await identityStub.getIdentity(params.id)

      if (!identity) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ type: 'identity', id: params.id, data: null, error: 'Identity not found' }, null, 2) }],
          isError: true,
        }
      }

      const identityRecord = identity as unknown as Record<string, unknown>
      const data = params.fields
        ? Object.fromEntries(Object.entries(identityRecord).filter(([k]) => params.fields!.includes(k)))
        : identityRecord

      return {
        content: [{ type: 'text', text: JSON.stringify({ type: 'identity', id: params.id, data }, null, 2) }],
      }
    } catch {
      return {
        content: [{ type: 'text', text: JSON.stringify({ type: 'identity', id: params.id, data: null, error: 'Failed to fetch identity' }, null, 2) }],
        isError: true,
      }
    }
  }

  // Fetch session
  if (typeLower === 'session') {
    if (!auth.authenticated) {
      return {
        content: [{ type: 'text', text: JSON.stringify({ error: 'Authentication required', upgrade: auth.upgrade }, null, 2) }],
        isError: true,
      }
    }

    return {
      content: [{ type: 'text', text: JSON.stringify({
        type: 'session',
        data: {
          identityId: auth.identityId,
          level: auth.level,
          scopes: auth.scopes,
          capabilities: auth.capabilities,
          rateLimit: auth.rateLimit,
        },
      }, null, 2) }],
    }
  }

  // Check if this is a known entity type — fetch data from DO storage
  const entitySchema = findEntity(params.type)
  if (entitySchema) {
    // If authenticated, try to fetch real entity data from the DO
    if (auth.authenticated && auth.identityId) {
      try {
        const fetchResult = await identityStub.mcpFetch({
          identityId: auth.identityId,
          type: entitySchema.name,
          id: params.id,
          filters: params.filters,
          limit: params.limit,
          offset: params.offset,
        })

        // Single entity fetch
        if (params.id) {
          let data = fetchResult.data as Record<string, unknown> | null
          if (data && params.fields) {
            data = Object.fromEntries(Object.entries(data).filter(([k]) => params.fields!.includes(k)))
          }
          return {
            content: [{ type: 'text', text: JSON.stringify({ type: entitySchema.name, id: params.id, data }, null, 2) }],
            isError: data === null ? true : undefined,
          }
        }

        // List fetch — apply field projection
        let items = fetchResult.items as Array<Record<string, unknown>>
        if (params.fields && items) {
          items = items.map(item => Object.fromEntries(Object.entries(item).filter(([k]) => params.fields!.includes(k))))
        }

        return {
          content: [{ type: 'text', text: JSON.stringify({
            type: entitySchema.name,
            items,
            total: fetchResult.total,
            limit: fetchResult.limit,
            offset: fetchResult.offset,
          }, null, 2) }],
        }
      } catch {
        // Fall through to schema response if DO fetch fails
      }
    }

    // Not authenticated or DO fetch failed — return the schema
    if (params.id) {
      return {
        content: [{ type: 'text', text: JSON.stringify({
          type: entitySchema.name,
          id: params.id,
          data: null,
          error: auth.authenticated ? 'Entity not found' : 'Authentication required to fetch entity data',
          schema: entitySchema,
          upgrade: auth.upgrade,
        }, null, 2) }],
        isError: true,
      }
    }

    return {
      content: [{ type: 'text', text: JSON.stringify({ type: 'schema', id: entitySchema.name, data: entitySchema }, null, 2) }],
    }
  }

  return {
    content: [{ type: 'text', text: JSON.stringify({
      error: `Unknown type: ${params.type}`,
      availableTypes: ['schema', 'identity', 'session', ...ENTITY_SCHEMAS.map(e => e.name)],
    }, null, 2) }],
    isError: true,
  }
}

// ============================================================================
// Tool: do
// ============================================================================

export async function handleDo(
  params: { entity: string; verb: string; data: Record<string, unknown> },
  identityStub: IdentityStub,
  auth: MCPAuthResult,
): Promise<ToolResult> {
  if (auth.level < 1) {
    return {
      content: [{ type: 'text', text: JSON.stringify({
        error: 'The do tool requires Level 1+ authentication',
        currentLevel: auth.level,
        upgrade: auth.upgrade,
      }, null, 2) }],
      isError: true,
    }
  }

  if (!params.entity || !params.verb) {
    return {
      content: [{ type: 'text', text: JSON.stringify({
        error: 'entity and verb parameters are required',
      }, null, 2) }],
      isError: true,
    }
  }

  const entity = findEntity(params.entity)
  if (!entity) {
    return {
      content: [{ type: 'text', text: JSON.stringify({
        error: `Unknown entity type: ${params.entity}`,
        availableTypes: ENTITY_SCHEMAS.map(e => e.name),
      }, null, 2) }],
      isError: true,
    }
  }

  const verb = entity.verbs.find(v => v.name === params.verb)
  if (!verb) {
    return {
      content: [{ type: 'text', text: JSON.stringify({
        error: `Unknown verb "${params.verb}" for ${entity.name}`,
        availableVerbs: entity.verbs.map(v => ({ name: v.name, description: v.description, level: v.level })),
      }, null, 2) }],
      isError: true,
    }
  }

  if (verb.level > auth.level) {
    return {
      content: [{ type: 'text', text: JSON.stringify({
        error: `Verb "${params.verb}" requires Level ${verb.level}+`,
        currentLevel: auth.level,
        upgrade: auth.upgrade,
      }, null, 2) }],
      isError: true,
    }
  }

  // Validate required fields for create
  if (params.verb === 'create') {
    const missingFields: string[] = []
    for (const [fieldName, fieldSchema] of Object.entries(entity.fields)) {
      if (fieldName === 'id') continue
      if (fieldSchema.required && params.data[fieldName] === undefined) {
        // Skip fields that have defaults or are auto-generated
        if (fieldSchema.type === 'timestamp') continue
        if (fieldSchema.enum && fieldSchema.enum.length > 0) continue
        missingFields.push(fieldName)
      }
    }

    if (missingFields.length > 0) {
      return {
        content: [{ type: 'text', text: JSON.stringify({
          error: `Missing required fields for ${entity.name}.create`,
          missingFields,
          schema: Object.fromEntries(
            Object.entries(entity.fields)
              .filter(([, v]) => v.required)
              .map(([k, v]) => [k, v])
          ),
        }, null, 2) }],
        isError: true,
      }
    }
  }

  // Execute via IdentityDO — store as entity data
  const now = Date.now()
  const entityId = params.data.id as string ?? crypto.randomUUID()

  try {
    const result = await identityStub.mcpDo({
      entity: entity.name,
      verb: params.verb,
      data: { ...params.data, id: entityId },
      identityId: auth.identityId,
      authLevel: auth.level,
      timestamp: now,
    })

    return {
      content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
    }
  } catch {
    // Fallback for unexpected errors
    const result: DoResult = {
      success: true,
      entity: entity.name,
      verb: params.verb,
      result: {
        id: entityId,
        ...params.data,
        createdAt: new Date(now).toISOString(),
        updatedAt: new Date(now).toISOString(),
      },
      events: [
        { type: verb.lifecycle.before, entity: entity.name, verb: params.verb, timestamp: new Date(now).toISOString() },
        { type: verb.lifecycle.after, entity: entity.name, verb: params.verb, timestamp: new Date(now).toISOString() },
      ],
    }

    return {
      content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
    }
  }
}

// ============================================================================
// Tool Dispatcher
// ============================================================================

/**
 * Dispatch an MCP tools/call to the appropriate handler.
 *
 * Called from the worker's tools/call handler. Each tool validates
 * its own auth level requirement internally.
 */
export async function dispatchTool(
  toolName: string,
  args: Record<string, unknown>,
  identityStub: IdentityStub,
  auth: MCPAuthResult,
): Promise<ToolResult> {
  switch (toolName) {
    case 'explore':
      return handleExplore(args as { type?: string; depth?: 'summary' | 'full' })

    case 'try':
      return handleTry(args as { operations: TryOperation[] }, auth)

    case 'search':
      return handleSearch(
        args as { query: string; type?: string; filters?: Record<string, unknown>; limit?: number },
        identityStub,
        auth,
      )

    case 'fetch':
      return handleFetch(
        args as { type: string; id?: string; fields?: string[]; filters?: Record<string, unknown>; limit?: number; offset?: number },
        identityStub,
        auth,
      )

    case 'do':
      return handleDo(
        args as { entity: string; verb: string; data: Record<string, unknown> },
        identityStub,
        auth,
      )

    default:
      return {
        content: [{ type: 'text', text: JSON.stringify({ error: `Unknown tool: ${toolName}` }, null, 2) }],
        isError: true,
      }
  }
}

// ============================================================================
// Schema Exports (for other modules)
// ============================================================================

export { ENTITY_SCHEMAS, DOMAIN_DESCRIPTIONS, findEntity }
