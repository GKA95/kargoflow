import React, { useEffect, useState, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { AlertCircle, Check, Copy, ExternalLink, Loader2 } from 'lucide-react';

interface GoogleAuthButtonProps {
  role: 'customer' | 'rider' | 'admin';
  onSuccess?: () => void;
  onError?: (errorMsg: string) => void;
  className?: string;
}

declare global {
  interface Window {
    google?: any;
  }
}

export const GoogleAuthButton: React.FC<GoogleAuthButtonProps> = ({
  role,
  onSuccess,
  onError,
  className = '',
}) => {
  const { googleLogin } = useAuth();
  const navigate = useNavigate();
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [showConfigHelp, setShowConfigHelp] = useState(false);
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [isNativeRendered, setIsNativeRendered] = useState(false);

  const googleButtonContainerRef = useRef<HTMLDivElement>(null);
  const tokenClientRef = useRef<any>(null);

  const clientId = import.meta.env.VITE_GOOGLE_CLIENT_ID;
  const currentOrigin = typeof window !== 'undefined' ? window.location.origin : '';
  const redirectUri = `${currentOrigin}/auth/callback`;

  const copyToClipboard = (text: string, fieldName: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(fieldName);
    setTimeout(() => setCopiedField(null), 2000);
  };

  const handleAuthPayload = useCallback(
    async (payload: any) => {
      setIsLoading(true);
      setErrorMessage(null);
      try {
        const loggedInUser = await googleLogin(payload, role);
        const destination =
          loggedInUser?.role === 'rider' ? '/rider/dashboard' : '/customer/dashboard';

        if (onSuccess) {
          onSuccess();
        }
        navigate(destination, { replace: true });
      } catch (err: any) {
        const rawMsg = err?.message || err;
        const msg = typeof rawMsg === 'string' ? rawMsg : (rawMsg?.message || JSON.stringify(rawMsg) || 'Google authentication failed');
        setErrorMessage(msg);
        onError?.(msg);
      } finally {
        setIsLoading(false);
      }
    },
    [googleLogin, role, onSuccess, onError, navigate]
  );

  // Initialize Google Identity Services (GIS)
  useEffect(() => {
    if (!clientId) {
      return;
    }

    let isMounted = true;

    const setupGsi = () => {
      if (!window.google?.accounts) return;

      try {
        // 1. Initialize Credential Manager with FedCM disabled to prevent NotAllowedError
        window.google.accounts.id.initialize({
          client_id: clientId,
          callback: async (response: any) => {
            if (response?.credential && isMounted) {
              await handleAuthPayload({ idToken: response.credential });
            }
          },
          auto_select: false,
          use_fedcm_for_prompt: false, // Prevents FedCM get() rejects with NotAllowedError in iframes
          itp_support: true,
        });

        // 2. Render Google's native Sign-In button into container
        if (googleButtonContainerRef.current) {
          googleButtonContainerRef.current.innerHTML = '';
          window.google.accounts.id.renderButton(googleButtonContainerRef.current, {
            type: 'standard',
            theme: 'outline',
            size: 'large',
            text: 'continue_with',
            shape: 'rectangular',
            logo_alignment: 'left',
            width: 320,
          });
          if (isMounted) {
            setIsNativeRendered(true);
          }
        }

        // 3. Initialize OAuth 2.0 Token Client for tap interactions
        if (window.google.accounts.oauth2) {
          tokenClientRef.current = window.google.accounts.oauth2.initTokenClient({
            client_id: clientId,
            scope: 'openid email profile',
            callback: async (tokenResponse: any) => {
              if (tokenResponse?.error) {
                const rawDetail = tokenResponse.error_description || tokenResponse.error;
                const errDetail = typeof rawDetail === 'string' ? rawDetail : JSON.stringify(rawDetail);
                if (errDetail.includes('origin') || tokenResponse.error === 'origin_mismatch') {
                  setShowConfigHelp(true);
                }
                setErrorMessage(`Google sign-in error: ${errDetail}`);
                onError?.(errDetail);
                setIsLoading(false);
                return;
              }
              if (tokenResponse?.access_token && isMounted) {
                await handleAuthPayload({ accessToken: tokenResponse.access_token });
              }
            },
          });
        }
      } catch (err: any) {
        console.warn('[GSI Setup]', err);
      }
    };

    if (window.google?.accounts) {
      setupGsi();
    } else {
      const existingScript = document.getElementById('google-gsi-script');
      if (!existingScript) {
        const script = document.createElement('script');
        script.id = 'google-gsi-script';
        script.src = 'https://accounts.google.com/gsi/client';
        script.async = true;
        script.defer = true;
        script.onload = () => setupGsi();
        document.head.appendChild(script);
      } else {
        existingScript.addEventListener('load', setupGsi);
      }
    }

    return () => {
      isMounted = false;
    };
  }, [clientId, handleAuthPayload, onError]);

  // Listen for OAuth Popup callbacks via window.postMessage
  useEffect(() => {
    const handleMessage = async (event: MessageEvent) => {
      if (event.data?.type === 'GOOGLE_AUTH_CALLBACK') {
        const { code, accessToken, idToken, error } = event.data;
        if (error) {
          const cleanErr = typeof error === 'string' ? error : JSON.stringify(error);
          if (cleanErr.includes('origin') || cleanErr.includes('redirect_uri')) {
            setShowConfigHelp(true);
          }
          setErrorMessage(`Google OAuth error: ${cleanErr}`);
          onError?.(cleanErr);
          setIsLoading(false);
          return;
        }

        if (code) {
          await handleAuthPayload({ code, redirectUri });
        } else if (accessToken) {
          await handleAuthPayload({ accessToken });
        } else if (idToken) {
          await handleAuthPayload({ idToken });
        }
      }
    };

    window.addEventListener('message', handleMessage);
    return () => window.removeEventListener('message', handleMessage);
  }, [handleAuthPayload, onError, redirectUri]);

  // Direct Button Tap Handler (frictionless, no forced prompt to prevent phone verification)
  const handleButtonClick = () => {
    if (!clientId) {
      setErrorMessage('Google Client ID is not configured.');
      onError?.('Google Client ID not configured');
      return;
    }

    setErrorMessage(null);
    setIsLoading(true);

    // Primary: Google Identity Services OAuth 2.0 Token Client popup (no prompt: 'select_account' to avoid phone prompt)
    if (tokenClientRef.current) {
      try {
        tokenClientRef.current.requestAccessToken();
        return;
      } catch (err: any) {
        console.warn('[TokenClient Prompt Failed, falling back to popup]', err);
      }
    }

    // Secondary: Open Google OAuth 2.0 Popup directly
    const oauthUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
    oauthUrl.searchParams.set('client_id', clientId);
    oauthUrl.searchParams.set('redirect_uri', redirectUri);
    oauthUrl.searchParams.set('response_type', 'token id_token');
    oauthUrl.searchParams.set('scope', 'openid email profile');
    oauthUrl.searchParams.set('nonce', Math.random().toString(36).substring(2));

    const popupWidth = 520;
    const popupHeight = 630;
    const left = window.screenX + (window.outerWidth - popupWidth) / 2;
    const top = window.screenY + (window.outerHeight - popupHeight) / 2;

    const popup = window.open(
      oauthUrl.toString(),
      'google_oauth_popup',
      `width=${popupWidth},height=${popupHeight},left=${left},top=${top},status=no,menubar=no`
    );

    if (!popup) {
      setIsLoading(false);
      setErrorMessage('Popup was blocked by your browser. Please allow popups for this site and try again.');
    }
  };

  return (
    <div className={`w-full ${className}`}>
      {/* Official Native Google Button if rendered by Google Identity Services */}
      <div
        ref={googleButtonContainerRef}
        className={`w-full flex justify-center ${isNativeRendered ? 'min-h-[44px]' : 'hidden'}`}
      />

      {/* Styled Fallback / Direct Button when native script is initializing */}
      {!isNativeRendered && (
        <button
          type="button"
          onClick={handleButtonClick}
          disabled={isLoading}
          className="w-full relative flex items-center justify-center gap-3 py-2.5 px-4 rounded-lg border border-slate-300 bg-white hover:bg-slate-50 active:bg-slate-100 text-slate-700 text-sm font-medium transition-all shadow-xs disabled:opacity-60 cursor-pointer"
        >
          {isLoading ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin text-teal-600" />
              <span>Connecting with Google...</span>
            </>
          ) : (
            <>
              <svg className="w-4 h-4 shrink-0" viewBox="0 0 24 24">
                <path
                  fill="#4285F4"
                  d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                />
                <path
                  fill="#34A853"
                  d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                />
                <path
                  fill="#FBBC05"
                  d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
                />
                <path
                  fill="#EA4335"
                  d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
                />
              </svg>
              <span>Continue with Google</span>
            </>
          )}
        </button>
      )}

      {/* Persistent helper toggle for Google Cloud Console origins */}
      <div className="mt-1.5 text-center">
        <button
          type="button"
          onClick={() => setShowConfigHelp(!showConfigHelp)}
          className="text-[11px] text-slate-400 hover:text-teal-700 transition-colors inline-flex items-center gap-1 font-medium cursor-pointer"
        >
          <span>{showConfigHelp ? 'Hide OAuth origin settings' : 'Fix "Error 400: origin_mismatch" / Configure Origins'}</span>
        </button>
      </div>

      {/* Error Notice */}
      {errorMessage && (
        <div className="mt-2.5 p-3 rounded-lg bg-amber-50 border border-amber-200 text-amber-800 text-xs">
          <div className="flex items-start gap-2">
            <AlertCircle className="w-4 h-4 shrink-0 text-amber-600 mt-0.5" />
            <div className="flex-1">
              <p className="font-medium">{typeof errorMessage === 'string' ? errorMessage : JSON.stringify(errorMessage)}</p>
            </div>
          </div>
        </div>
      )}

      {/* Google Cloud Console Setup Guidance */}
      {showConfigHelp && (
        <div className="mt-3 p-3.5 bg-slate-900 text-slate-100 rounded-lg text-xs space-y-3 shadow-md">
          <div className="flex items-center justify-between border-b border-slate-700 pb-2">
            <span className="font-semibold text-teal-400">Google Cloud Console Configuration</span>
            <a
              href="https://console.cloud.google.com/apis/credentials"
              target="_blank"
              rel="noreferrer"
              className="text-slate-400 hover:text-white flex items-center gap-1 text-[11px]"
            >
              <span>Open Console</span>
              <ExternalLink className="w-3 h-3" />
            </a>
          </div>

          <p className="text-slate-300 leading-relaxed text-[11px]">
            In Google Cloud Console under <strong>APIs &amp; Services &gt; Credentials &gt; OAuth 2.0 Client IDs</strong>, ensure your Web Client ID includes these URLs:
          </p>

          <div>
            <div className="text-slate-400 font-mono text-[10px] uppercase mb-1">
              Authorized JavaScript Origins:
            </div>
            <div className="flex items-center justify-between bg-slate-800 rounded px-2.5 py-1.5 border border-slate-700">
              <code className="text-teal-300 font-mono text-[11px] truncate select-all">{currentOrigin}</code>
              <button
                type="button"
                onClick={() => copyToClipboard(currentOrigin, 'origin')}
                className="ml-2 text-slate-300 hover:text-white"
                title="Copy origin"
              >
                {copiedField === 'origin' ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
          </div>

          <div>
            <div className="text-slate-400 font-mono text-[10px] uppercase mb-1">
              Authorized Redirect URIs:
            </div>
            <div className="flex items-center justify-between bg-slate-800 rounded px-2.5 py-1.5 border border-slate-700">
              <code className="text-teal-300 font-mono text-[11px] truncate select-all">{redirectUri}</code>
              <button
                type="button"
                onClick={() => copyToClipboard(redirectUri, 'redirect')}
                className="ml-2 text-slate-300 hover:text-white"
                title="Copy redirect URI"
              >
                {copiedField === 'redirect' ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
