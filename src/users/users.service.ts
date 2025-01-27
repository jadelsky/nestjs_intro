import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './users.entity';


@Injectable()
export class UsersService {
    constructor(
        @InjectRepository(User)
        private usersRepository: Repository<User>,
    ) {}

    async findAll(): Promise<User[]> {
        return this.usersRepository.find();
    }

    async findOne(id: number): Promise<User | null> {
        return this.usersRepository.findOne({ where: { id } });
    }

    async findOneByUsername(name: string): Promise<User | null> {
        return this.usersRepository.findOne({ where: { name } });
    }

    async create(user: User): Promise<User> {
        const newUser = this.usersRepository.create(user);
        return this.usersRepository.save(newUser);
    }

    async update(id: number, user: User): Promise<User> {
        await this.usersRepository.update(id, user);
        const updatedUser = await this.usersRepository.findOne({ where: { id } });

        if (!updatedUser) {
            throw new Error(`User with id ${id} not found`);
        }

        return updatedUser;
    }

    async delete(id: number): Promise<void> {
        this.usersRepository.delete(id);
    }
}
