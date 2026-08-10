import { useEffect, useRef, useState } from 'react';
import { infraApi } from '../services/api';
import { restartPollAttempts } from '../utils/restartPoll';

export type RestartStatus = 'idle' | 'restarting' | 'waiting' | 'success' | 'error';

export interface RestartOpenRequest {
  profiles: string[];
  dbSwitch: boolean;
  storageSwitch: boolean;
}

export interface RestartFlow {
  showRestartModal: boolean;
  restartCountdown: number;
  restartStatus: RestartStatus;
  pendingProfiles: string[];
  previousProfiles: string[];
  dbSwitch: boolean;
  storageSwitch: boolean;
  open: (req: RestartOpenRequest) => void;
  close: () => void;
  start: () => void;
}

/**
 * Owns the post-save restart modal: the show/countdown/status state machine, the pending/previous
 * profile pair that drives `infraApi.restart(...)`, and the db/storage-switch flags the modal's
 * data-loss warning reads (#488). `open()` is the single entry point a caller (the page's save
 * `onSaved`) uses to hand over a fresh save result.
 *
 * The profile pair is one state object rotated by a single functional update, not two separate
 * setters reading each other's render-scoped value — React StrictMode double-invokes updater
 * functions, which would otherwise make the rotation order fragile.
 */
export function useRestartFlow(): RestartFlow {
  const [showRestartModal, setShowRestartModal] = useState(false);
  const [restartCountdown, setRestartCountdown] = useState(0);
  const [restartStatus, setRestartStatus] = useState<RestartStatus>('idle');
  const [profiles, setProfiles] = useState<{ pending: string[]; previous: string[] }>({
    pending: [],
    previous: [],
  });
  // Set when the just-saved config changes the DB or storage backend vs what's running, so the restart
  // modal can warn that the new backend starts empty and offer a data backup before switching (#488).
  const [dbSwitch, setDbSwitch] = useState(false);
  const [storageSwitch, setStorageSwitch] = useState(false);

  const open = ({
    profiles: newProfiles,
    dbSwitch: nextDbSwitch,
    storageSwitch: nextStorageSwitch,
  }: RestartOpenRequest) => {
    setProfiles(prev => ({ previous: prev.pending, pending: newProfiles }));
    setDbSwitch(nextDbSwitch);
    setStorageSwitch(nextStorageSwitch);
    setShowRestartModal(true);
  };

  // Dismissal is only offered in the idle state — while a restart is running there is deliberately
  // no way to close the progress view. Shared by the modal's onClose and the "Later" button; both
  // only ever fire while idle, since "Later" is rendered exclusively inside the idle branch.
  const close = () => {
    if (restartStatus === 'idle') setShowRestartModal(false);
  };

  // Every timer this flow arms, tracked so unmount can clear them. Navigating away mid-restart
  // previously left the recursive 1s health poll running against unmounted state for up to
  // maxAttempts, and its success branch could fire window.location.reload() from a page the user
  // had long left. The countdown interval was also uncloseable on the error path.
  const timersRef = useRef<Set<ReturnType<typeof setTimeout>>>(new Set());
  const countdownIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const mountedRef = useRef(true);

  const stopCountdown = () => {
    if (countdownIntervalRef.current) {
      clearInterval(countdownIntervalRef.current);
      countdownIntervalRef.current = null;
    }
  };

  const armTimeout = (fn: () => void, ms: number) => {
    const timer = setTimeout(() => {
      timersRef.current.delete(timer);
      fn();
    }, ms);
    timersRef.current.add(timer);
  };

  useEffect(() => {
    mountedRef.current = true; // re-armed on StrictMode's mount→cleanup→mount cycle
    const timers = timersRef.current;
    return () => {
      mountedRef.current = false;
      for (const timer of timers) clearTimeout(timer);
      timers.clear();
      stopCountdown();
    };
  }, []);

  const checkServerHealth = (estimatedTime?: number) => {
    let attempts = 0;
    const maxAttempts = restartPollAttempts(estimatedTime);

    const check = async () => {
      try {
        await infraApi.healthCheck();
        if (!mountedRef.current) return;
        stopCountdown();
        setRestartCountdown(0);
        setRestartStatus('success');
        armTimeout(() => window.location.reload(), 2000);
      } catch {
        if (!mountedRef.current) return;
        attempts++;
        if (attempts < maxAttempts) {
          armTimeout(() => void check(), 1000);
        } else {
          // Also stop the ticking countdown — the error path previously had no way to reach the
          // interval's clear, so it kept firing until the page unloaded.
          stopCountdown();
          setRestartStatus('error');
        }
      }
    };

    armTimeout(() => void check(), 3000);
  };

  const start = async () => {
    setRestartStatus('restarting');
    setRestartCountdown(30);

    const profilesToRemove = profiles.previous.filter(p => !profiles.pending.includes(p));

    // Kept outside the try: the poll deadline is derived from it, and the restart call is expected to
    // fail sometimes (the server may go down before it answers).
    let estimatedTime: number | undefined;
    try {
      const response = await infraApi.restart(profiles.pending, profilesToRemove);
      estimatedTime = response.estimatedTime;
      if (response.estimatedTime) setRestartCountdown(response.estimatedTime);
    } catch {
      // Expected — server shutting down
    }
    if (!mountedRef.current) return;

    setRestartStatus('waiting');
    stopCountdown();
    countdownIntervalRef.current = setInterval(() => {
      setRestartCountdown(prev => {
        if (prev <= 1) {
          stopCountdown();
          return 0;
        }
        return prev - 1;
      });
    }, 1000);

    checkServerHealth(estimatedTime);
  };

  return {
    showRestartModal,
    restartCountdown,
    restartStatus,
    pendingProfiles: profiles.pending,
    previousProfiles: profiles.previous,
    dbSwitch,
    storageSwitch,
    open,
    close,
    start,
  };
}
