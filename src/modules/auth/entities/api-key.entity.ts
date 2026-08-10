import { Entity, Column, PrimaryGeneratedColumn, CreateDateColumn, UpdateDateColumn, Index } from 'typeorm';

export enum ApiKeyRole {
  ADMIN = 'admin',
  OPERATOR = 'operator',
  VIEWER = 'viewer',
}

@Entity('api_keys')
export class ApiKey {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column({ type: 'varchar', length: 100 })
  name!: string;

  @Index({ unique: true })
  @Column({ type: 'varchar', length: 64 })
  keyHash!: string;

  // 12 to fit the 12-char prefix that auth.service writes (was varchar(8); harmless on the
  // hardcoded-SQLite `main` connection, but kept consistent with the code).
  @Column({ type: 'varchar', length: 12 })
  keyPrefix!: string;

  @Column({
    type: 'varchar',
    length: 20,
    default: ApiKeyRole.OPERATOR,
  })
  role!: ApiKeyRole;

  @Column({ type: 'simple-array', nullable: true })
  allowedIps!: string[] | null;

  @Column({ type: 'simple-array', nullable: true })
  allowedSessions!: string[] | null;

  @Column({ type: 'boolean', default: true })
  isActive!: boolean;

  @Column({ type: 'datetime', nullable: true })
  expiresAt!: Date | null;

  @Column({ type: 'datetime', nullable: true })
  lastUsedAt!: Date | null;

  @Column({ type: 'int', default: 0 })
  usageCount!: number;

  // Two-factor authentication (TOTP / Google Authenticator). Only ADMIN keys may enrol (enforced in
  // the controller). `mfaEnabled` flips true only after a code is confirmed; while a secret is being
  // set up but not yet confirmed it is stored with `mfaEnabled=false`. `mfaSecret` is the TOTP shared
  // secret, AES-256-GCM encrypted at rest (recoverable — see mfa.service.ts), never the raw base32.
  // When `mfaEnabled` is true the key becomes interactive-only: the ApiKeyGuard refuses it as a plain
  // bearer credential unless a valid post-TOTP dashboard session token accompanies it.
  @Column({ type: 'boolean', default: false })
  mfaEnabled!: boolean;

  @Column({ type: 'text', nullable: true })
  mfaSecret!: string | null;

  @Column({ type: 'datetime', nullable: true })
  mfaEnrolledAt!: Date | null;

  @CreateDateColumn()
  createdAt!: Date;

  @UpdateDateColumn()
  updatedAt!: Date;
}
