import { Controller, Get, Body, Param, Delete, Put, NotFoundException, UsePipes, ValidationPipe } from '@nestjs/common';
import { UsersService } from './users.service';
import { User } from './users.entity';
import { ApiTags } from '@nestjs/swagger';
import { DeleteUserSwagger, GetUsersSwagger, GetUserSwagger, UpdateUserSwagger } from './../swagger.decorator';
import { UserUpdateDto } from './dto/userUpdate.dto';

@ApiTags('users')
@Controller('users')
export class UsersController {
    constructor(private readonly usersService: UsersService) {}

    @Get()
    @GetUsersSwagger()
    async findAll(): Promise<User[]> {
        return this.usersService.findAll();
    }

    @Get(':id')
    @GetUserSwagger()
    async findOne(@Param('id') id: string): Promise<User> {
        const user = await this.usersService.findOne(+id);
        if (!user) {
            throw new NotFoundException(`User with id ${id} not found`);
        } else {
            return user;
        }
    }

    @Put(':id')
    @UpdateUserSwagger()
    async update(@Param('id') id: string, @Body() user: UserUpdateDto): Promise<User> {
        return this.usersService.update(+id, user);
    }

    @Delete(':id')
    @DeleteUserSwagger()
    async delete(@Param('id') id: string): Promise<void> {
        const user = await this.usersService.findOne(+id);
        if (!user) {
            throw new Error(`User with id ${id} not found`);
        } else {
        return this.usersService.delete(+id);
        }
    }
}
