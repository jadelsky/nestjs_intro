import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';
import * as fs from 'fs';
import * as path from 'path';
import * as Handlebars from 'handlebars';

@Injectable()
export class EmailService {
  private verificationTemplate: Handlebars.TemplateDelegate;
  private resetTemplate: Handlebars.TemplateDelegate;

  constructor(private readonly configService: ConfigService) {
    this.verificationTemplate = this.loadAndCompileTemplate('verification-email.hbs');
    this.resetTemplate = this.loadAndCompileTemplate('password-reset-email.hbs');
  }

  private loadAndCompileTemplate(templateName: string): Handlebars.TemplateDelegate {
    const templatePath = path.resolve(__dirname, '../mail/templates', templateName);
    const templateSource = fs.readFileSync(templatePath, 'utf8');
    return Handlebars.compile(templateSource);
  }

  private get transporter() {
    const port = this.configService.getOrThrow<number>('SMTP_PORT');
    return nodemailer.createTransport({
      host: this.configService.getOrThrow<string>('SMTP_HOST'),
      port,
      secure: port === 465,
      auth: {
        user: this.configService.getOrThrow<string>('SMTP_USER'),
        pass: this.configService.getOrThrow<string>('SMTP_PASS'),
      },
    });
  }

  async sendVerificationEmail(to: string, verificationUrl: string) {
    const html = this.verificationTemplate({ verificationUrl });

    await this.transporter.sendMail({
      from: this.configService.getOrThrow<string>('MAIL_FROM'),
      to,
      subject: 'Please verify your email',
      html,
    });
  }

  async sendPasswordResetEmail(to: string, resetUrl: string, denyUrl?: string) {
    const html = this.resetTemplate({ resetUrl, denyUrl });

    await this.transporter.sendMail({
      from: this.configService.getOrThrow<string>('MAIL_FROM'),
      to,
      subject: 'Reset Your Password',
      html,
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