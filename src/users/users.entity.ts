import { IsEmail } from 'class-validator';
import { Entity, Column, PrimaryGeneratedColumn, BeforeInsert } from 'typeorm';
import { v4 as uuidv4 } from 'uuid';

export enum UserRole {
  ADMIN = 'admin',
  USER = 'user',
}

@Entity()
export class User {
  @PrimaryGeneratedColumn()
  id: number; // Internal use only

  @Column({ unique: true })
  publicId: string; // External APIs

  @BeforeInsert()
  generatePublicId() {
    this.publicId = uuidv4();
  }

  @Column()
  username: string;

  @Column()
  @IsEmail()
  email: string;

  @Column({ default: false })
  emailVerified: boolean;

  @Column()
  password: string;

  @Column({type: 'enum', enum: UserRole, default: UserRole.USER})
  role: UserRole;

  @Column({ default: true })
  allowUsernameReset : boolean;
  
}