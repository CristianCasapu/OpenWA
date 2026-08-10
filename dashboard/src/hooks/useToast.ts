import { createContext, useContext } from 'react';

export type ToastType = 'success' | 'error' | 'warning' | 'info';

export interface Toast {
  id: string;
  type: ToastType;
  title: string;
  message?: string;
  duration?: number;
  /** Stable, non-rendered key for de-duplicating recurring toasts. Independent of the (translated) title. */
  dedupeKey?: string;
}

export interface ToastContextValue {
  toasts: Toast[];
  addToast: (toast: Omit<Toast, 'id'>) => void;
  removeToast: (id: string) => void;
  success: (title: string, message?: string) => void;
  /**
   * `err` is the original thrown error, when the caller has one: the connection-loss de-dupe then
   * classifies on the structured status/code api.ts attaches instead of substring-matching the
   * rendered text. Optional so text-only call sites keep working.
   */
  error: (title: string, message?: string, err?: unknown) => void;
  warning: (title: string, message?: string) => void;
  info: (title: string, message?: string) => void;
}

export const ToastContext = createContext<ToastContextValue | null>(null);

export function useToast() {
  const context = useContext(ToastContext);
  if (!context) {
    throw new Error('useToast must be used within a ToastProvider');
  }
  return context;
}
