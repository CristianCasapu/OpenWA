import { useState, useEffect, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { ShieldCheck, ShieldOff, Loader2, AlertTriangle, Copy } from 'lucide-react';
import { mfaApi, DASHBOARD_SESSION_STORAGE_KEY, type MfaSetupResponse } from '../services/api';
import { useToast } from '../hooks/useToast';
import { copyToClipboard } from '../utils/clipboard';
import './MfaPanel.css';

type View = 'loading' | 'disabled' | 'setup' | 'enabled' | 'disabling';

/**
 * Two-factor authentication (TOTP / Google Authenticator) for the CURRENT session's admin key.
 * Enabling makes the key interactive-only: it will no longer authenticate headless API clients, so a
 * clear warning is shown and a separate operator key is recommended for automation.
 */
export function MfaPanel() {
  const { t } = useTranslation();
  const toast = useToast();
  const [view, setView] = useState<View>('loading');
  const [busy, setBusy] = useState(false);
  const [enrollment, setEnrollment] = useState<MfaSetupResponse | null>(null);
  const [code, setCode] = useState('');
  const [error, setError] = useState('');

  const loadStatus = useCallback(async () => {
    try {
      const { enabled } = await mfaApi.status();
      setView(enabled ? 'enabled' : 'disabled');
    } catch {
      setView('disabled');
    }
  }, []);

  useEffect(() => {
    void loadStatus();
  }, [loadStatus]);

  const beginSetup = async () => {
    setBusy(true);
    setError('');
    try {
      setEnrollment(await mfaApi.setup());
      setCode('');
      setView('setup');
    } catch (e) {
      toast.error(t('apiKeys.mfa.setupFailed'), e instanceof Error ? e.message : undefined);
    } finally {
      setBusy(false);
    }
  };

  const confirmEnable = async () => {
    const cleaned = code.replace(/\s+/g, '');
    if (!/^\d{6}$/.test(cleaned)) {
      setError(t('apiKeys.mfa.invalidCode'));
      return;
    }
    setBusy(true);
    setError('');
    try {
      const res = await mfaApi.enable(cleaned);
      // The current key is now interactive-only; keep this session alive with the returned token.
      sessionStorage.setItem(DASHBOARD_SESSION_STORAGE_KEY, res.sessionToken);
      setEnrollment(null);
      setView('enabled');
      toast.success(t('apiKeys.mfa.enabledToast'));
    } catch {
      setError(t('apiKeys.mfa.invalidCode'));
    } finally {
      setBusy(false);
    }
  };

  const confirmDisable = async () => {
    const cleaned = code.replace(/\s+/g, '');
    if (!/^\d{6}$/.test(cleaned)) {
      setError(t('apiKeys.mfa.invalidCode'));
      return;
    }
    setBusy(true);
    setError('');
    try {
      await mfaApi.disable(cleaned);
      setCode('');
      setView('disabled');
      toast.success(t('apiKeys.mfa.disabledToast'));
    } catch {
      setError(t('apiKeys.mfa.invalidCode'));
    } finally {
      setBusy(false);
    }
  };

  const cancel = () => {
    setEnrollment(null);
    setCode('');
    setError('');
    void loadStatus();
  };

  const codeInput = (
    <div className="mfa-code-row">
      <input
        type="text"
        inputMode="numeric"
        autoComplete="one-time-code"
        maxLength={6}
        value={code}
        onChange={e => setCode(e.target.value.replace(/[^\d]/g, ''))}
        placeholder={t('apiKeys.mfa.codePlaceholder')}
        className={error ? 'error' : ''}
      />
      {error && <span className="mfa-error">{error}</span>}
    </div>
  );

  return (
    <section className="mfa-panel">
      <div className="mfa-panel-header">
        {view === 'enabled' ? <ShieldCheck size={20} /> : <ShieldOff size={20} />}
        <div>
          <h3>{t('apiKeys.mfa.title')}</h3>
          <p className="mfa-subtitle">{t('apiKeys.mfa.subtitle')}</p>
        </div>
        <span className={`mfa-status ${view === 'enabled' ? 'on' : 'off'}`}>
          {view === 'enabled' ? t('apiKeys.mfa.on') : t('apiKeys.mfa.off')}
        </span>
      </div>

      {view === 'loading' && <Loader2 className="animate-spin" size={20} />}

      {view === 'disabled' && (
        <div className="mfa-body">
          <div className="mfa-warning">
            <AlertTriangle size={16} /> {t('apiKeys.mfa.interactiveOnlyWarning')}
          </div>
          <button className="btn-primary" onClick={() => void beginSetup()} disabled={busy}>
            {busy ? <Loader2 className="animate-spin" size={16} /> : <ShieldCheck size={16} />}
            {t('apiKeys.mfa.enable')}
          </button>
        </div>
      )}

      {view === 'setup' && enrollment && (
        <div className="mfa-body">
          <p>{t('apiKeys.mfa.scanInstruction')}</p>
          <img className="mfa-qr" src={enrollment.qrDataUrl} alt={t('apiKeys.mfa.qrAlt')} />
          <div className="mfa-secret">
            <span>{t('apiKeys.mfa.manualKey')}</span>
            <code>{enrollment.secret}</code>
            <button
              className="btn-secondary btn-sm"
              onClick={() => {
                void copyToClipboard(enrollment.secret).then(ok => ok && toast.success(t('apiKeys.mfa.secretCopied')));
              }}
            >
              <Copy size={14} /> {t('apiKeys.mfa.copy')}
            </button>
          </div>
          <label className="mfa-code-label">{t('apiKeys.mfa.enterCodeToConfirm')}</label>
          {codeInput}
          <div className="mfa-actions">
            <button className="btn-secondary" onClick={cancel} disabled={busy}>
              {t('common.cancel')}
            </button>
            <button className="btn-primary" onClick={() => void confirmEnable()} disabled={busy}>
              {busy ? <Loader2 className="animate-spin" size={16} /> : null}
              {t('apiKeys.mfa.confirmEnable')}
            </button>
          </div>
        </div>
      )}

      {view === 'enabled' && (
        <div className="mfa-body">
          <p className="mfa-enabled-note">{t('apiKeys.mfa.enabledNote')}</p>
          <button className="btn-secondary" onClick={() => setView('disabling')} disabled={busy}>
            <ShieldOff size={16} /> {t('apiKeys.mfa.disable')}
          </button>
        </div>
      )}

      {view === 'disabling' && (
        <div className="mfa-body">
          <label className="mfa-code-label">{t('apiKeys.mfa.enterCodeToDisable')}</label>
          {codeInput}
          <div className="mfa-actions">
            <button className="btn-secondary" onClick={cancel} disabled={busy}>
              {t('common.cancel')}
            </button>
            <button className="btn-danger" onClick={() => void confirmDisable()} disabled={busy}>
              {busy ? <Loader2 className="animate-spin" size={16} /> : null}
              {t('apiKeys.mfa.confirmDisable')}
            </button>
          </div>
        </div>
      )}
    </section>
  );
}
