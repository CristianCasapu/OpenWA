import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Eye, EyeOff, Languages, ShieldCheck } from 'lucide-react';
import { GithubIcon } from '../components/GithubIcon';
import { CustomSelect } from '../components/CustomSelect';
import { languageOptions, resolveSupportedLanguage, type SupportedLanguage } from '../i18n';
import { API_BASE_URL, DASHBOARD_SESSION_STORAGE_KEY } from '../services/api';
import './Login.css';

interface LoginProps {
  onLogin: (apiKey: string) => void;
  /** When set, the key already validated but needs a 2FA code — start at the code step (session lapsed). */
  resumeKey?: string;
}

export function Login({ onLogin, resumeKey }: LoginProps) {
  const { t, i18n } = useTranslation();
  const [apiKey, setApiKey] = useState(resumeKey ?? '');
  const [showKey, setShowKey] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  // Two-factor: after a key with 2FA validates, we ask for the authenticator code before granting.
  const [step, setStep] = useState<'key' | 'code'>(resumeKey ? 'code' : 'key');
  const [code, setCode] = useState('');
  const currentLang = resolveSupportedLanguage(i18n.resolvedLanguage || i18n.language);

  const changeLanguage = (language: SupportedLanguage) => {
    void i18n.changeLanguage(language);
  };

  const handleKeySubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!apiKey.trim()) {
      setError(t('login.apiKeyRequired'));
      return;
    }
    setIsLoading(true);
    setError('');
    try {
      const response = await fetch(`${API_BASE_URL}/auth/validate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': apiKey },
      });
      if (response.ok) {
        const data = (await response.json().catch(() => ({}))) as { mfaRequired?: boolean };
        if (data.mfaRequired) {
          setStep('code'); // ask for the authenticator code before completing login
        } else {
          onLogin(apiKey);
        }
      } else {
        const errorData = (await response.json().catch(() => ({}))) as { message?: string };
        setError(errorData.message || t('login.invalidKey'));
      }
    } catch {
      setError(t('login.connectionError'));
    } finally {
      setIsLoading(false);
    }
  };

  const handleCodeSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleaned = code.replace(/\s+/g, '');
    if (!/^\d{6}$/.test(cleaned)) {
      setError(t('login.mfa.invalidCode'));
      return;
    }
    setIsLoading(true);
    setError('');
    try {
      const response = await fetch(`${API_BASE_URL}/auth/mfa/session`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': apiKey },
        body: JSON.stringify({ code: cleaned }),
      });
      if (response.ok) {
        const data = (await response.json()) as { sessionToken: string };
        sessionStorage.setItem(DASHBOARD_SESSION_STORAGE_KEY, data.sessionToken);
        onLogin(apiKey);
      } else {
        setError(t('login.mfa.invalidCode'));
      }
    } catch {
      setError(t('login.connectionError'));
    } finally {
      setIsLoading(false);
    }
  };

  const backToKey = () => {
    setStep('key');
    setCode('');
    setError('');
  };

  return (
    <div className="login-container">
      <div className="login-card">
        <div className="login-logo">
          <img src="/openwa_logo.webp" alt="OpenWA" className="logo-icon" />
          <span className="version-info">
            {t('login.version', {
              version: __APP_VERSION__,
              date: new Date(__BUILD_TIME__).toISOString().slice(0, 10).replace(/-/g, ''),
            })}
          </span>
        </div>

        <div className="login-language">
          <Languages size={18} />
          <CustomSelect
            value={currentLang}
            onChange={value => changeLanguage(value as SupportedLanguage)}
            options={languageOptions.map(opt => ({ value: opt.value, label: opt.label }))}
            ariaLabel={t('common.language')}
          />
        </div>

        {step === 'key' ? (
          <form onSubmit={handleKeySubmit} className="login-form">
            <div className="input-group">
              <label htmlFor="apiKey">{t('login.apiKey')}</label>
              <div className="input-wrapper">
                <input
                  id="apiKey"
                  type={showKey ? 'text' : 'password'}
                  value={apiKey}
                  onChange={e => setApiKey(e.target.value)}
                  placeholder={t('login.apiKeyPlaceholder')}
                  className={error ? 'error' : ''}
                />
                <button
                  type="button"
                  className="toggle-visibility"
                  onClick={() => setShowKey(!showKey)}
                  aria-label={showKey ? t('common.hideApiKey') : t('common.showApiKey')}
                >
                  {showKey ? <EyeOff size={20} /> : <Eye size={20} />}
                </button>
              </div>
              {error && <span className="error-message">{error}</span>}
            </div>

            <button type="submit" className="connect-btn" disabled={isLoading}>
              {isLoading ? t('login.connecting') : t('login.connect')}
            </button>
          </form>
        ) : (
          <form onSubmit={handleCodeSubmit} className="login-form">
            <div className="input-group">
              <label htmlFor="mfaCode">
                <ShieldCheck size={16} style={{ verticalAlign: 'text-bottom', marginInlineEnd: 6 }} />
                {t('login.mfa.title')}
              </label>
              <input
                id="mfaCode"
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={6}
                value={code}
                onChange={e => setCode(e.target.value.replace(/[^\d]/g, ''))}
                placeholder={t('login.mfa.codePlaceholder')}
                className={error ? 'error' : ''}
                autoFocus
              />
              <small className="mfa-hint">{t('login.mfa.hint')}</small>
              {error && <span className="error-message">{error}</span>}
            </div>

            <button type="submit" className="connect-btn" disabled={isLoading}>
              {isLoading ? t('login.connecting') : t('login.mfa.verify')}
            </button>
            <button type="button" className="mfa-back-btn" onClick={backToKey} disabled={isLoading}>
              {t('login.mfa.back')}
            </button>
          </form>
        )}

        <p className="login-help">
          {t('login.help')}{' '}
          <a href="https://docs.open-wa.org" target="_blank" rel="noopener noreferrer">
            {t('login.viewDocs')}
          </a>
        </p>
      </div>

      <footer className="login-footer">
        <span>{t('login.footer')}</span>
        <a
          href="https://github.com/rmyndharis/OpenWA"
          target="_blank"
          rel="noopener noreferrer"
          className="github-link"
          aria-label="GitHub"
        >
          <GithubIcon size={18} />
        </a>
      </footer>
    </div>
  );
}
