import { extractDeviceModelFromUserAgent, formatDeviceModelName } from './userControl';

interface NavigatorWithUAData extends Navigator {
  userAgentData?: {
    platform?: string;
    mobile?: boolean;
    getHighEntropyValues?: (hints: string[]) => Promise<{
      model?: string;
      platform?: string;
      platformVersion?: string;
    }>;
  };
}

export async function detectBrowserDeviceName(): Promise<string> {
  if (typeof navigator === 'undefined') return '';

  const nav = navigator as NavigatorWithUAData;
  try {
    if (nav.userAgentData?.getHighEntropyValues) {
      const hints = await nav.userAgentData.getHighEntropyValues([
        'model',
        'platform',
        'platformVersion',
      ]);
      const formattedHint = formatDeviceModelName(hints.model);
      if (formattedHint) {
        return formattedHint;
      }
    }
  } catch {
    // Client Hints API may be blocked by permissions policy
  }

  const fromUa = extractDeviceModelFromUserAgent(nav.userAgent);
  if (fromUa) {
    return fromUa;
  }

  if (/android/i.test(nav.userAgent)) {
    return 'Android Smartphone';
  }
  return '';
}
