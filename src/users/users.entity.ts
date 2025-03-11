import { Exclude } from 'class-transformer';
import { IsEmail } from 'class-validator';
import { Entity, Column, PrimaryGeneratedColumn } from 'typeorm';

export enum UserRole {
  ADMIN = 'admin',
  USER = 'user',
}

@Entity()
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  username: string;

  @Column()
  @IsEmail()
  email: string;

  @Column()
  @Exclude()
  password: string;

  @Column({type: 'enum', enum: UserRole, default: UserRole.USER})
  role: UserRole;
  
}