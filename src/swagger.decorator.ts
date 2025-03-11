import { ApiBearerAuth, ApiBody, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { applyDecorators } from '@nestjs/common';
import { UserUpdateDto } from './users/dto/userUpdate.dto';  
import { UserCreateDto } from './users/dto/userCreate.dto';  
import { SignInDto } from './auth/dto/sign-in.dto';
import { RefreshDto } from './auth/dto/refresh.dto';

// USERS CONTROLLER DECORATORS
export function GetUsersSwagger(): MethodDecorator {
    return applyDecorators(
      ApiOperation({ summary: 'Get all users' }),      
      ApiBearerAuth('access-token'),
      ApiResponse({ status: 200, description: 'List of ALL users.' }),
      ApiResponse({ status: 500, description: 'Internal server error' })
    );
  }

  export function GetUserSwagger(): MethodDecorator {
    return applyDecorators(
      ApiOperation({ summary: 'Get user by ID' }),
      ApiBearerAuth('access-token'),
      ApiResponse({ status: 200, description: 'User by ID' }),
      ApiResponse({ status: 500, description: 'Internal server error' })
    );
  }

  export function UpdateUserSwagger(): MethodDecorator {
    return applyDecorators(
      ApiOperation({ summary: 'Update user by ID' }),
      ApiBearerAuth('access-token'),
      ApiResponse({ status: 200, description: 'Updated User by ID' }),
      ApiResponse({ status: 400, description: 'Error: Bad Request' }),
      ApiResponse({ status: 500, description: 'Internal server error' }),
      ApiBody({ 
        description: 'User update payload', 
        type: UserUpdateDto })
    );
  }

  export function DeleteUserSwagger(): MethodDecorator {
    return applyDecorators(
      ApiOperation({ summary: 'Delete user by ID' }),
      ApiBearerAuth('access-token'),
      ApiResponse({ status: 200, description: 'Deleted User by ID' }),
      ApiResponse({ status: 500, description: 'Internal server error' })
    );
  }

  // AUTH CONTROLLER DECORATORS
  export function LoginUserSwagger(): MethodDecorator {
    return applyDecorators(
      ApiOperation({ summary: 'Login user with username and password' }),
      ApiResponse({ status: 200, description: 'User logged in' }),
      ApiResponse({ status: 500, description: 'Internal server error' }),
      ApiBody({ 
        description: 'User login payload', 
        type: SignInDto })
    );
  }

  export function RegisterUserSwagger(): MethodDecorator {
    return applyDecorators(
      ApiOperation({ summary: 'Register user' }),
      ApiResponse({ status: 200, description: 'User registered' }),
      ApiResponse({ status: 400, description: 'Error: Bad Request' }),
      ApiResponse({ status: 500, description: 'Internal server error' }),
      ApiBody({ 
        description: 'User login payload', 
        type: UserCreateDto })
    );
  }

    export function RefreshTokenSwagger(): MethodDecorator {
      return applyDecorators(
        ApiOperation({ summary: 'Reissue access token using Refresh token ' }),
        ApiResponse({ status: 200, description: 'Access token reissued' }),
        ApiResponse({ status: 400, description: 'Error: Bad Request' }),
        ApiResponse({ status: 500, description: 'Internal server error' }),
        ApiBody({ 
          description: 'Refresh token payload', 
          type: RefreshDto })
      );
  }