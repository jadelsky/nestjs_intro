import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './users.entity';
import { UserUpdateDto } from './dto/userUpdate.dto';
import { instanceToPlain } from 'class-transformer';
import * as bcrypt from 'bcryptjs';

@Injectable()
export class UsersService {
    constructor(
        @InjectRepository(User)
        private usersRepository: Repository<User>,
    ) {}

    async findAll(): Promise<object[]> {
        const users = await this.usersRepository.find();
        return users.map(user => instanceToPlain(user));
    }

    async findOne(id: number): Promise<object | null> {
        const user = await this.usersRepository.findOne({ where: { id } });
        return user ? instanceToPlain(user) : null;
    }

    async findOneByUsername(username: string): Promise<User | null> {
        return this.usersRepository.findOne({ where: { username } });
    }

    async update(id: number, user: UserUpdateDto): Promise<object> {
        const existingUser = await this.usersRepository.findOne({ where: { id } });
        
        if (!existingUser) {
            throw new NotFoundException(`User with id ${id} not found`);
        }

        const updatedData: Partial<UserUpdateDto> = {};

        if (user.password) {
            const salt = await bcrypt.genSalt(10);
            updatedData.password = await bcrypt.hash(user.password, salt);
        } 

        if (user.username) {
            updatedData.username = user.username;
        }
        if (user.email) {
            updatedData.email = user.email;
        }

        if (Object.keys(updatedData).length === 0) {
            throw new BadRequestException('No data provided to update');
        }

        await this.usersRepository.update(id, updatedData);
        const updatedUser = await this.usersRepository.findOne({ where: { id } });

        return instanceToPlain(updatedUser);
    }

    async delete(id: number): Promise<void> {
        this.usersRepository.delete(id);
    }
}
