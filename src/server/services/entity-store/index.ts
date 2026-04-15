/**
 * Entity Store — Domain 9
 *
 * Owns: generic indexed entity storage on Durable Object storage
 * Depends on: Foundation (0)
 * Key types: EntityStoreService
 * Storage keys: entity:{owner}:{type}:{id}, idx:{owner}:{type}:{field}:{value}:{id}
 */

export { EntityStoreServiceImpl } from './service'
export type { EntityStoreService } from './service'
