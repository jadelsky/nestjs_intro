import { readFileSync } from 'fs';
import * as path from 'path';

export function loadTemplate(fileName: string): string {
  const filePath = path.join(__dirname, '../templates', fileName);
  return readFileSync(filePath, 'utf8');
}

export function renderTemplate(template: string, params: Record<string, string>): string {
  return Object.entries(params).reduce(
    (result, [key, value]) => result.replaceAll(`{{${key}}}`, value ?? ''),
    template,
  );
}