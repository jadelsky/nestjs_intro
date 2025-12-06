export default () => ({
  JWT_SECRET: process.env.JWT_SECRET!,
  JWT_EXPIRATION: parseInt(process.env.JWT_EXPIRATION ?? '1', 10), // in hours
  REFRESH_SECRET: process.env.REFRESH_SECRET!,
  REFRESH_EXPIRATION: parseInt(process.env.REFRESH_EXPIRATION ?? '7', 10), // in days

  EMAIL_VERIFICATION_SECRET: process.env.EMAIL_VERIFICATION_SECRET!,
  EMAIL_VERIFICATION_EXPIRATION: parseInt(process.env.EMAIL_VERIFICATION_EXPIRATION ?? '1', 10), // in days

  PASSWORD_RESET_SECRET: process.env.PASSWORD_RESET_SECRET!,
  PASSWORD_RESET_EXPIRATION: parseInt(process.env.PASSWORD_RESET_EXPIRATION ?? '1', 10), // in hours

  PASSWORD_RESET_DENY_SECRET: process.env.PASSWORD_RESET_DENY_SECRET!,
  PASSWORD_RESET_DENY_EXPIRATION: parseInt(process.env.PASSWORD_RESET_DENY_EXPIRATION ?? '1', 10), // in hours

  SMTP_HOST: process.env.SMTP_HOST!,
  SMTP_PORT: Number(process.env.SMTP_PORT!),
  SMTP_USER: process.env.SMTP_USER!,
  SMTP_PASS: process.env.SMTP_PASS!,
  MAIL_FROM: process.env.MAIL_FROM ?? 'no-reply@example.com',
});