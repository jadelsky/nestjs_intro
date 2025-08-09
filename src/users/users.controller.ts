import { Controller, Get, Body, Param, Delete, Patch, NotFoundException, UsePipes, ValidationPipe, UseGuards  } from '@nestjs/common';
import { UsersService } from './users.service';
import { ApiTags } from '@nestjs/swagger';
import { DeleteUserSwagger, GetUsersSwagger, GetUserSwagger, UpdateUserSwagger } from './../swagger.decorator';
import { UserUpdateDto } from './dto/userUpdate.dto';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RolesGuard } from '../guards/roles.guard';
import { Roles } from '../decorators/roles.decorator';

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
    @Roles('admin')
    @Patch(':id')
    @UpdateUserSwagger()
    async update(@Param('id') id: string, @Body() user: UserUpdateDto): Promise<object> {
        return this.usersService.update(+id, user);
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
