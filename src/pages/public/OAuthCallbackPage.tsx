import React, { useEffect } from 'react';

export const OAuthCallbackPage: React.FC = () => {
  useEffect(() => {
    try {
      const urlParams = new URLSearchParams(window.location.search);
      const hashParams = new URLSearchParams(window.location.hash.replace(/^#/, ''));
      const code = urlParams.get('code');
      const accessToken = hashParams.get('access_token');
      const idToken = hashParams.get('id_token');
      const error = urlParams.get('error') || hashParams.get('error');

      if (window.opener) {
        window.opener.postMessage(
          {
            type: 'GOOGLE_AUTH_CALLBACK',
            code,
            accessToken,
            idToken,
            error,
          },
          '*'
        );
        setTimeout(() => window.close(), 500);
      } else {
        window.location.href = '/';
      }
    } catch (e) {
      console.error('[OAuth Callback]', e);
    }
  }, []);

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-50 font-sans">
      <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm text-center max-w-sm">
        <div className="w-8 h-8 border-2 border-teal-600 border-t-transparent rounded-full animate-spin mx-auto mb-3" />
        <h3 className="text-sm font-semibold text-slate-800">Authenticating with Google...</h3>
        <p className="text-xs text-slate-500 mt-1">This window will close automatically.</p>
      </div>
    </div>
  );
};
