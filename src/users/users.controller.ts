import { Controller, Get, Body, Param, Delete, Patch, NotFoundException, UseGuards, Req, ForbiddenException  } from '@nestjs/common';
import { UsersService } from './users.service';
import { ApiTags } from '@nestjs/swagger';
import { DeleteUserSwagger, GetUsersSwagger, GetUserSwagger, UpdateUserSwagger } from './../swagger.decorator';
import { UserUpdateDto } from './dto/userUpdate.dto';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RolesGuard } from '../guards/roles.guard';
import { Roles } from '../decorators/roles.decorator';
import { User } from './users.entity';
import { Request } from 'express';

@ApiTags('users')
@Controller('users')
@UseGuards(JwtAuthGuard, RolesGuard)
export class UsersController {
    constructor(private readonly usersService: UsersService) {}

    @UseGuards(JwtAuthGuard)
    @Roles('admin')
    @GetUsersSwagger()
    @Get()
    async findAll(): Promise<object[]> {
        return this.usersService.findAll();
    }

    @UseGuards(JwtAuthGuard)
    @Roles('admin')
    @Get(':id')
    @GetUserSwagger()
    async findOne(@Param('id') id: string): Promise<object> {
        const user = await this.usersService.findOne(+id);
        if (!user) {
            throw new NotFoundException(`User with id ${id} not found`);
        } else {
            return user;
        }
    }

    @UseGuards(JwtAuthGuard)
    @Patch(':id')
    @UpdateUserSwagger()
    async update(@Param('id') id: string, @Body() user: UserUpdateDto, @Req() req: Request): Promise<object> {
        const requester = req.user as User;

        if (requester.role === 'admin') {
            return this.usersService.updateByAnyId(id, user);
        }
        if (requester.role === 'user') {
            if (id !== requester.publicId) {
                throw new ForbiddenException('You can only update your own account.');
            }

            if (user.role) {
                throw new ForbiddenException('You cannot change your role.');
            }

            // Strip out role field and allow only email/password
            const allowedUpdate = {
                email: user.email,
                password: user.password,
            };

            return this.usersService.updateByPublicId(id, allowedUpdate);
        }

        throw new ForbiddenException('Unauthorized');
    }

    @UseGuards(JwtAuthGuard)
    @Roles('admin')
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
