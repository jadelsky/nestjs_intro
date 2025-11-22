import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';

@Injectable()
export class EmailService {
  private transporter;

  constructor(private configService: ConfigService) {
    this.transporter = nodemailer.createTransport({
      host: this.configService.get<string>('SMTP_HOST'),
      port: Number(this.configService.get<string>('SMTP_PORT')),
      secure: false, // true for port 465, false for others
      auth: {
        user: this.configService.get<string>('SMTP_USER'),
        pass: this.configService.get<string>('SMTP_PASS'),
      },
    });
  }

  async sendVerificationEmail(to: string, verificationUrl: string) {
    await this.transporter.sendMail({
      from: this.configService.get<string>('MAIL_FROM'),
      to,
      subject: 'Please verify your email',
      html: `
        <p>Thanks for registering!</p>
        <p>Please verify your email by clicking the link below:</p>
        <a href="${verificationUrl}">${verificationUrl}</a>
      `,
    });
  }

  async sendPasswordResetEmail(to: string, resetUrl: string, denyUrl?: string) {
    await this.transporter.sendMail({
      from: this.configService.get<string>('MAIL_FROM'),
      to,
      subject: 'Reset Your Password',
      html: `
      <p>Hello,</p>

      <p>We received a request to reset your password. You can choose a new one by clicking the link below:</p>

      <p>
        <a href="${resetUrl}" style="font-weight: bold; color: #3b82f6;">
          Reset your password
        </a>
      </p>

      <p>If you did not request a password reset, you can safely ignore this email.</p>

      ${denyUrl
          ? `
        <p style="margin-top: 20px; color: #555;">
          Didn’t request this at all?  
          <a href="${denyUrl}" style="color: #ef4444;">
            Disable password reset via username
          </a>
        </p>
      `
          : ''
        }

      <p style="margin-top: 30px; font-size: 12px; color: #999;">
        This link will expire in 1 hour.
      </p>
    `,
    });
  }


  public maskEmail(email: string): string {
    const [local, domain] = email.split('@');
    const maskedLocal = local.length <= 2
      ? local[0] + '*'
      : local[0] + '*'.repeat(local.length - 2) + local[local.length - 1];

    return `${maskedLocal}@${domain}`;
  }

}