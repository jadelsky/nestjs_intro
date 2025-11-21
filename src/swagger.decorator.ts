import { ApiBearerAuth, ApiBody, ApiQuery, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { applyDecorators } from '@nestjs/common';
import { UserUpdateDto } from './users/dto/userUpdate.dto';
import { UserCreateDto } from './users/dto/userCreate.dto';
import { SignInDto } from './auth/dto/sign-in.dto';
import { RefreshDto } from './auth/dto/refresh.dto';
import { ResendVerificationDto } from './auth/dto/resend-verification.dto';

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
      type: UserUpdateDto
    })
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
      type: SignInDto
    })
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
      type: UserCreateDto
    })
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
      type: RefreshDto
    })
  );
}

export function VerifyEmailSwagger(): MethodDecorator {
  return applyDecorators(
    ApiOperation({ summary: 'Verify user email using verification token' }),
    ApiQuery({ name: 'token', description: 'Email verification JWT token', required: true }),
    ApiResponse({ status: 200, description: 'Email verified successfully' }),
    ApiResponse({ status: 400, description: 'Invalid or expired token' }),
    ApiResponse({ status: 404, description: 'User not found' }),
    ApiResponse({ status: 500, description: 'Internal server error' }),
  );
}

export function ResendVerificationEmailSwagger(): MethodDecorator {
  return applyDecorators(
    ApiOperation({ summary: 'Resend email verification link to user' }),

    ApiBody({
      description: 'Email of the user requesting a new verification token',
      type: ResendVerificationDto 
    }),

    ApiResponse({ status: 200, description: 'Verification email sent successfully' }),
    ApiResponse({ status: 400, description: 'Invalid request or email already verified' }),
    ApiResponse({ status: 404, description: 'User not found'}),
    ApiResponse({ status: 429, description: 'Too many resend attempts (rate limited)'}),
    ApiResponse({ status: 500, description: 'Internal server error'}),
  );
}
